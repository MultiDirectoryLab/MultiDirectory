"""RFC 5424 Syslog message serializer.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import socket
from datetime import datetime, timezone
from typing import Any

from ldap_protocol.policies.audit.events.dataclasses import (
    NormalizedAuditEvent,
)


class RFC5424Serializer:
    """Serializer for RFC 5424 compliant syslog messages."""

    NILVALUE: str = "-"
    UTF8_BOM: str = "\ufeff"

    # SD-ID suffix for STRUCTURED-DATA: audit@32473
    # Change to your registered Private Enterprise Number (PEN)
    STRUCTURED_DATA_ID_SUFFIX: str = "32473"

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

    def __init__(
        self,
        app_name: str,
        facility: str,
    ) -> None:
        """Initialize RFC 5424 serializer."""
        self.app_name = app_name
        self.facility = facility

    def serialize(
        self,
        event: NormalizedAuditEvent,
        structured_data: dict[str, Any],
        syslog_version: int,
    ) -> str:
        """Serialize audit event to RFC 5424 format."""
        severity = self._format_severity(event.severity)
        timestamp = self._format_timestamp(event.timestamp)
        hostname = self._format_hostname(event.hostname)
        app_name = self._format_field(self.app_name, 48)
        proc_id = self._format_field(event.service_name, 128)
        msg_id = self._format_field(event.event_type, 32)
        sd_str = self._format_structured_data(structured_data)
        msg = self._format_message(event.syslog_message)

        return (
            f"<{severity}>{syslog_version} "
            f"{timestamp} {hostname} {app_name} {proc_id} {msg_id} "
            f"{sd_str}{msg}"
        )

    def _format_severity(self, severity: int) -> int:
        """Calculate PRIORITY value (RFC 5424 section 6.2.1)."""
        if not 0 <= severity <= 7:
            raise NotImplementedError(f"Severity must be 0-7, got {severity}")

        facility_code = self.SYSLOG_FACILITIES.get(
            self.facility.lower(),
            self.SYSLOG_FACILITIES["authpriv"],
        )

        return (facility_code << 3) | severity

    def _format_timestamp(self, timestamp: float) -> str:
        """Format TIMESTAMP field (RFC 5424 section 6.2.3)."""
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _format_hostname(self, hostname: str | None) -> str:
        """Format HOSTNAME field (RFC 5424 section 6.2.4)."""
        if not hostname:
            hostname = socket.gethostname()

        return self._format_field(hostname, 255)

    def _format_field(
        self,
        value: str | None,
        max_length: int,
    ) -> str:
        """Format generic RFC 5424 field."""
        if not value:
            return self.NILVALUE

        sanitized = "".join(c for c in value if 33 <= ord(c) <= 126)[
            :max_length
        ]

        return sanitized or self.NILVALUE

    def _format_structured_data(
        self,
        structured_data: dict[str, Any],
    ) -> str:
        """Format STRUCTURED-DATA field (RFC 5424 section 6.3)."""
        if not structured_data:
            return self.NILVALUE

        params = []
        for key, value in structured_data.items():
            param_name = self._sanitize_param_name(str(key))
            if not param_name:
                continue

            param_value = self._escape_param_value(str(value))
            params.append(f'{param_name}="{param_value}"')

        if not params:
            return self.NILVALUE

        sd_id = f"audit@{self.STRUCTURED_DATA_ID_SUFFIX}"
        return f"[{sd_id} {' '.join(params)}]"

    def _sanitize_param_name(self, name: str) -> str:
        """Sanitize PARAM-NAME for STRUCTURED-DATA.

        RFC 5424 allows only printable ASCII (33-126)
        except: =, space, ], "
        Max length: 32 characters
        """
        return "".join(
            c
            for c in name
            if 33 <= ord(c) <= 126 and c not in ("=", " ", "]", '"')
        )[:32]

    def _escape_param_value(self, value: str) -> str:
        """Escape PARAM-VALUE for STRUCTURED-DATA."""
        return (
            value.replace("\\", "\\\\").replace('"', r"\"").replace("]", r"\]")
        )

    def _format_message(self, msg: str | None) -> str:
        """Format MSG field (RFC 5424 section 6.4)."""
        if not msg:
            return ""

        return f" {self.UTF8_BOM}{msg}"
