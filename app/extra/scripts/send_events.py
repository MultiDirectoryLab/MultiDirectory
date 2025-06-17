"""Send events.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import socket
import ssl
from abc import ABC, abstractmethod
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from audit_models import AuditLog
from config import Settings
from ioc import AuditLogger, EventAsyncSession
from models import (
    AuditDestination,
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
)


class SendersABC(ABC):
    """Senders abstract base class."""

    _destination: AuditDestination

    def __init__(self, destination: AuditDestination) -> None:
        """Initialize SendersABC."""
        self._destination = destination

    @abstractmethod
    async def send(self, event: AuditLog) -> None:
        """Send event."""

    @property
    @abstractmethod
    def service_name(self) -> AuditDestinationServiceType:
        """Get service name."""


class SyslogSender(SendersABC):
    """Syslog sender."""

    service_name: AuditDestinationServiceType = (
        AuditDestinationServiceType.SYSLOG
    )
    SYSLOG_VERSION = 1
    DEFAULT_TIMEOUT = 10
    DEFAULT_FACILITY = "authpriv"
    _SYSLOG_FACILITIES = {
        "kernel": 0,
        "user": 1,
        "mail": 2,
        "system": 3,
        "security": 4,
        "syslog": 5,
        "printer": 6,
        "network": 7,
        "uucp": 8,
        "clock": 9,
        "authpriv": 10,
        "ftp": 11,
        "ntp": 12,
        "audit": 13,
        "alert": 14,
        "cron": 15,
        "local0": 16,
        "local1": 17,
        "local2": 18,
        "local3": 19,
        "local4": 20,
        "local5": 21,
        "local6": 22,
        "local7": 23,
    }
    DEFAULT_APP_NAME = "MultiDirectory"

    async def _send_udp(self, message: str) -> None:
        """Send UDP."""
        transport, _ = await asyncio.wait_for(
            asyncio.get_event_loop().create_datagram_endpoint(
                lambda: asyncio.DatagramProtocol(),
                remote_addr=(self._destination.host, self._destination.port),
            ),
            timeout=self.DEFAULT_TIMEOUT,
        )
        transport.sendto(message.encode("utf-8"))
        transport.close()

    async def _send_tcp(self, message: str) -> None:
        """Send TCP."""
        try:
            ssl_context = None
            use_tls = (
                self._destination.protocol == AuditDestinationProtocolType.TLS
            )

            if use_tls:
                ssl_context = ssl.create_default_context(
                    ssl.Purpose.SERVER_AUTH,
                    cadata=self._destination.ca_cert_data
                    if self._destination.ca_cert_data
                    else None,
                )

                if not self._destination.tls_verify_cert:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

                if (
                    self._destination.client_cert_data
                    and self._destination.client_key_data
                ):
                    ssl_context.load_cert_chain(
                        certfile=self._destination.client_cert_data,
                        keyfile=self._destination.client_key_data,
                    )

            _, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=self._destination.host,
                    port=self._destination.port,
                    ssl=ssl_context if use_tls else None,
                ),
                timeout=self.DEFAULT_TIMEOUT,
            )

            writer.write(message.encode("utf-8"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        except Exception as e:
            logger.error(f"[{'TLS' if use_tls else 'TCP'} Error] {e}")
            raise

    def generate_rfc5424_message(
        self,
        event: AuditLog,
        structured_data: dict[str, Any],
    ) -> str:
        """Generate a syslog message according to RFC 5424."""
        severity_code = event.content["severity"]
        facility = self.DEFAULT_FACILITY
        app_name = self.DEFAULT_APP_NAME
        msg_id = event.id
        message = event.syslog_message
        hostname = event.content["hostname"]
        proc_id = event.content["service_name"]

        if not 0 <= severity_code <= 7:
            raise ValueError("Severity code must be between 0 and 7")

        facility_code = self._SYSLOG_FACILITIES.get(
            facility.lower(), self._SYSLOG_FACILITIES[self.DEFAULT_FACILITY]
        )
        priority = (facility_code << 3) | severity_code

        # TIMESTAMP (RFC 5424 section 6.2.3)
        timestamp = datetime.now(tz=timezone.utc).isoformat(
            timespec="milliseconds"
        )
        if "." in timestamp:
            timestamp = timestamp.replace("+00:00", "Z")

        # HOSTNAME (section 6.2.4)
        hostname = (hostname or socket.gethostname() or "-")[:255]

        # APP-NAME (section 6.2.5)
        app_name = app_name or "-"
        if len(app_name) > 48:
            app_name = app_name[:48]

        # PROCID (section 6.2.6)
        proc_id = proc_id or "-"

        # MSGID (section 6.2.7)
        msg_id = msg_id or "-"

        # STRUCTURED-DATA (section 6.3)
        sd_str = self._format_structured_data(app_name, structured_data) or "-"

        # MSG (section 6.4)
        message = self._escape_message(message) if message else ""

        return (
            f"<{priority}>{self.SYSLOG_VERSION} {timestamp} "
            f"{hostname} {app_name} {proc_id} {msg_id} "
            f"{sd_str}{message}"
        )

    def _escape_message(self, msg: str) -> str:
        """Escape special chars in message (RFC 5424 section 6.4)."""
        return " " + msg.replace("\n", " ").replace("\r", " ")

    def _format_structured_data(
        self, app_name: str, structured_data: dict[str, Any]
    ) -> str:
        """Format structured data according to RFC 5424 section 6.3."""
        if not structured_data:
            return ""

        def escape_param_value(value: str) -> str:
            return (
                value.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("]", "\\]")
            )

        sd_id = f"{app_name}@{ULID()}"
        params = []

        for k, v in structured_data.items():
            if not k or "=" in k or " " in k or '"' in k:
                continue
            escaped_value = escape_param_value(str(v))
            params.append(f'{k}="{escaped_value}"')

        if not params:
            return ""

        return f"[{sd_id} {' '.join(params)}]"

    async def send(self, event: AuditLog) -> None:
        """Send event."""
        structured_data = deepcopy(event.content)
        event_time = structured_data["timestamp"]
        dt = datetime.fromtimestamp(event_time, tz=timezone.utc)
        structured_data["iso_time"] = dt.isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        del structured_data["severity"]

        syslog_message = self.generate_rfc5424_message(
            event=event,
            structured_data=structured_data,
        )
        if self._destination.protocol == AuditDestinationProtocolType.UDP:
            callback = self._send_udp
        elif self._destination.protocol in {
            AuditDestinationProtocolType.TCP,
            AuditDestinationProtocolType.TLS,
        }:
            callback = self._send_tcp

        try:
            await callback(syslog_message)
        except TimeoutError as te:
            logger.error(f"[ERROR] Timeout during syslog send: {te}")
            raise
        except (OSError, ConnectionRefusedError, ConnectionError) as ce:
            logger.error(f"[ERROR] Failed to send syslog: {ce}")
            raise
        except Exception as e:
            logger.error(f"[ERROR] Unexpected error during syslog send: {e}")
            raise


senders: dict[AuditDestinationServiceType, type[SendersABC]] = {
    AuditDestinationServiceType.SYSLOG: SyslogSender,
}


def should_skip_event_retry(event: AuditLog, settings: Settings) -> bool:
    """Check if event should be skipped."""
    if not event.first_failed_at:
        return False

    if event.retry_count > 3:
        return True

    first_failed_utc = event.first_failed_at.astimezone(timezone.utc)
    time_passed = datetime.now(tz=timezone.utc) - first_failed_utc

    match event.retry_count:
        case 1:
            return time_passed < timedelta(
                minutes=settings.AUDIT_FIRST_RETRY_TIME
            )
        case 2:
            return time_passed < timedelta(
                minutes=settings.AUDIT_SECOND_RETRY_TIME
            )
        case 3:
            return time_passed < timedelta(
                minutes=settings.AUDIT_THIRD_RETRY_TIME
            )
        case _:
            return False


async def send_events(
    session: AsyncSession,
    event_session: EventAsyncSession,
    settings: Settings,
    audit_logger: AuditLogger,
) -> None:
    """Send events."""
    destinations = await session.scalars(
        select(AuditDestination)
        .filter_by(is_enabled=True)
    )  # fmt: skip

    if not destinations:
        return
    events = (
        await event_session.scalars(
            select(AuditLog)
            .with_for_update(skip_locked=True)
            .limit(20)
        )
    ).all()  # fmt: skip

    for server in destinations:
        sender = senders[server.service_type](server)

        for event in events:
            if event.server_delivery_status.get(server.id, False):
                continue

            if should_skip_event_retry(event, settings):
                continue

            try:
                await sender.send(event)
                event.server_delivery_status[server.id] = True
            except Exception as error:
                logger.error(f"Sending error: {error}")

                event.server_delivery_status[server.id] = False

                if event.first_failed_at is None:
                    event.first_failed_at = datetime.now(tz=timezone.utc)

                event.retry_count += 1

    await event_session.flush()

    for event in events:
        to_delete = False

        if event.first_failed_at:
            first_failed_utc = event.first_failed_at.astimezone(timezone.utc)
            time_passed = datetime.now(tz=timezone.utc) - first_failed_utc

            if (
                time_passed
                > timedelta(minutes=settings.AUDIT_THIRD_RETRY_TIME)
                or event.retry_count > 3
            ):
                audit_logger.info(f"{event.id} {event.content}\n")
                to_delete = True

        if (
            all(list(event.server_delivery_status.values()))
            and event.server_delivery_status
        ):
            to_delete = True

        if to_delete:
            await event_session.delete(event)

    await event_session.commit()
