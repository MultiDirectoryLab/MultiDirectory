"""Send events.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import socket
import ssl
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

from audit_models import AuditLog
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from ioc import EventAsyncSession
from models import (
    AuditDestination,
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
)

SYSLOG_FACILITIES = {
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
DEFAULT_FACILITY = "authpriv"
DEFAULT_APP_NAME = "MultiDirectory"
SYSLOG_VERSION = 1


def generate_rfc5424_message(
    severity_code: int,
    facility: str,
    app_name: str,
    msg_id: str,
    structured_data: dict[str, Any],
    message: str,
    hostname: str | None = None,
    proc_id: str | None = None,
) -> str:
    """Generate a syslog message according to RFC 5424."""
    if not 0 <= severity_code <= 7:
        raise ValueError("Severity code must be between 0 and 7")

    facility_code = SYSLOG_FACILITIES.get(
        facility.lower(), SYSLOG_FACILITIES[DEFAULT_FACILITY]
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
    sd_str = _format_structured_data(app_name, structured_data) or "-"

    # MSG (section 6.4)
    message = _escape_message(message) if message else ""
    logger.critical(
        f"RFC5424: {priority} {SYSLOG_VERSION} {timestamp} {hostname} {app_name} {proc_id} {msg_id} {sd_str}{message}"
    )
    return (
        f"<{priority}>{SYSLOG_VERSION} {timestamp} "
        f"{hostname} {app_name} {proc_id} {msg_id} "
        f"{sd_str}{message}"
    )


def _escape_message(msg: str) -> str:
    """Escape special chars in message (RFC 5424 section 6.4)."""
    return " " + msg.replace("\n", " ").replace("\r", " ")


def _format_structured_data(
    app_name: str, structured_data: dict[str, Any]
) -> str:
    """Format structured data according to RFC 5424 section 6.3."""
    if not structured_data:
        return ""

    def escape_param_value(value: str) -> str:
        return (
            value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
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


async def _send_udp(host: str, port: int, message: str) -> None:
    """Отправка через UDP."""
    transport, _ = await asyncio.wait_for(
        asyncio.get_event_loop().create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(host, port),
        ),
        timeout=10,
    )
    transport.sendto(message.encode("utf-8"))
    transport.close()


async def _send_tcp(
    host: str,
    port: int,
    message: str,
    use_tls: bool = False,
    tls_verify_cert: bool | None = None,
    ca_cert_data: str | None = None,
    client_cert_data: str | None = None,
    client_key_data: str | None = None,
) -> None:
    """Отправка через TCP с опциональным TLS."""
    try:
        ssl_context = None

        if use_tls:
            ssl_context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH,
                cafile=ca_cert_data if ca_cert_data else None,
            )

            if not tls_verify_cert:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            if client_cert_data and client_key_data:
                ssl_context.load_cert_chain(
                    certfile=client_cert_data, keyfile=client_key_data
                )

        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host, port=port, ssl=ssl_context if use_tls else None
            ),
            timeout=10,
        )

        writer.write(message.encode("utf-8"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    except Exception as e:
        logger.error(f"[{'TLS' if use_tls else 'TCP'} Error] {e}")
        raise


async def send_syslog(event: AuditLog, destination: AuditDestination) -> None:
    """Send event to syslog."""
    try:
        structured_data = deepcopy(event.content)
        event_time = structured_data["timestamp"]
        dt = datetime.fromtimestamp(event_time, tz=timezone.utc)
        structured_data["iso_time"] = dt.isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        del structured_data["severity"]

        rfc_message = generate_rfc5424_message(
            severity_code=event.content["severity"],
            facility="authpriv",
            app_name="MultiDirectory",
            msg_id=event.id,
            message=event.syslog_message,
            structured_data=structured_data,
            hostname=event.content["hostname"],
            proc_id=event.content["service_name"],
        )

        if destination.protocol == AuditDestinationProtocolType.UDP:
            await _send_udp(destination.host, destination.port, rfc_message)
        elif destination.protocol in {
            AuditDestinationProtocolType.TCP,
            AuditDestinationProtocolType.TLS,
        }:
            await _send_tcp(
                destination.host,
                destination.port,
                rfc_message,
                use_tls=destination.protocol
                == AuditDestinationProtocolType.TLS,
                tls_verify_cert=destination.tls_verify_cert,
                ca_cert_data=destination.ca_cert_data,
                client_cert_data=destination.client_cert_data,
                client_key_data=destination.client_key_data,
            )

    except TimeoutError as te:
        logger.error(f"[ERROR] Timeout during syslog send: {te}")
        raise
    except (OSError, ConnectionRefusedError, ConnectionError) as ce:
        logger.error(f"[ERROR] Failed to send syslog: {ce}")
        raise
    except Exception as e:
        logger.error(f"[ERROR] Unexpected error during syslog send: {e}")
        raise


async def send_events(
    session: AsyncSession, event_session: EventAsyncSession
) -> None:
    """Send events."""
    destinations = await session.scalars(select(AuditDestination))

    if not destinations:
        return
    events = (
        await event_session.scalars(
            select(AuditLog).with_for_update(skip_locked=True).limit(20)
        )
    ).all()

    for server in destinations:
        if server.service_type == AuditDestinationServiceType.SYSLOG:
            func = send_syslog

        for event in events:
            if event.server_delivery_status.get(server.id, False):
                continue

            try:
                await func(event, server)
                event.server_delivery_status[server.id] = True
            except Exception as error:
                logger.error(f"Sending error: {error}")

                event.server_delivery_status[server.id] = False

                if event.first_failed_at is None:
                    event.first_failed_at = datetime.now(tz=timezone.utc)

    await event_session.flush()

    for event in events:
        if event.first_failed_at:
            first_failed_utc = event.first_failed_at.replace(
                tzinfo=timezone.utc
            )
            time_passed = datetime.now(tz=timezone.utc) - first_failed_utc

            if time_passed > timedelta(hours=24):
                await event_session.delete(event)

        if (
            all(list(event.server_delivery_status.values()))
            and event.server_delivery_status.values()
        ):
            await event_session.delete(event)

        await event_session.flush()

    await event_session.commit()
