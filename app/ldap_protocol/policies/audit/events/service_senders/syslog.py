"""Syslog sender.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import socket
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from loguru import logger

from ldap_protocol.policies.audit.enums import (
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
)
from ldap_protocol.policies.audit.events.dataclasses import (
    NormalizedAuditEvent,
)

from .base import AuditDestinationSenderABC


class SyslogSender(AuditDestinationSenderABC):
    """Syslog sender."""

    service_name: AuditDestinationServiceType = (
        AuditDestinationServiceType.SYSLOG
    )
    SYSLOG_VERSION: int = 1
    DEFAULT_TIMEOUT: int = 10
    DEFAULT_FACILITY = "authpriv"
    SYSLOG_FACILITIES: dict[str, int] = {
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
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=self._destination.host,
                port=self._destination.port,
            ),
            timeout=self.DEFAULT_TIMEOUT,
        )

        writer.write(message.encode("utf-8"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    def generate_rfc5424_message(
        self,
        event: NormalizedAuditEvent,
        structured_data: dict[str, Any],
    ) -> str:
        """Generate a syslog message according to RFC 5424."""
        severity_code = event.severity
        facility = self.DEFAULT_FACILITY
        app_name = self.DEFAULT_APP_NAME
        msg_id = str(uuid.uuid4())
        message = event.syslog_message
        hostname = event.hostname
        proc_id = event.service_name

        if not 0 <= severity_code <= 7:
            raise ValueError("Severity code must be between 0 and 7")

        facility_code = self.SYSLOG_FACILITIES.get(
            facility.lower(),
            self.SYSLOG_FACILITIES[self.DEFAULT_FACILITY],
        )
        priority = (facility_code << 3) | severity_code

        # TIMESTAMP (RFC 5424 section 6.2.3)
        dt = datetime.fromtimestamp(event.timestamp, tz=timezone.utc)
        timestamp = dt.isoformat(
            timespec="milliseconds",
        ).replace("+00:00", "Z")

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
            f"{sd_str} {message}"
        )

    def _escape_message(self, msg: str) -> str:
        """Escape special chars in message (RFC 5424 section 6.4)."""
        return " " + msg.replace("\n", " ").replace("\r", " ")

    def _format_structured_data(
        self,
        app_name: str,
        structured_data: dict[str, Any],
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

        sd_id = f"{app_name}@{uuid.uuid4()}"
        params = []

        for k, v in structured_data.items():
            if not k or "=" in k or " " in k or '"' in k:
                continue
            escaped_value = escape_param_value(str(v))
            params.append(f'{k}="{escaped_value}"')

        if not params:
            return ""

        return f"[{sd_id} {' '.join(params)}]"

    async def send(self, event: NormalizedAuditEvent) -> None:
        """Send event."""
        structured_data = deepcopy(event.destination_dict)

        syslog_message = self.generate_rfc5424_message(
            event=event,
            structured_data=structured_data,
        )
        if self._destination.protocol == AuditDestinationProtocolType.UDP:
            callback = self._send_udp
        elif self._destination.protocol == AuditDestinationProtocolType.TCP:
            callback = self._send_tcp

        try:
            await callback(syslog_message)
        except TimeoutError as te:
            logger.error(
                f"Timeout during syslog {self._destination.name} send: {te}",
            )
            raise
        except (OSError, ConnectionRefusedError, ConnectionError) as ce:
            logger.error(
                f"Failed to send syslog {self._destination.name}: {ce}",
            )
            raise
        except Exception as e:
            logger.error(
                f"Error during syslog {self._destination.name} send: {e}",
            )
            raise
