"""Audit log data classes.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import json
import socket
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from loguru import logger
from pydantic import SecretStr

from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.objects import OperationEvent

from .enums import (
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
    AuditSeverity,
)


@dataclass
class AuditPolicySetupDTO:
    """Audit policy data transfer object."""

    object_class: str
    action: str
    is_success: bool
    severity: AuditSeverity
    is_enabled: bool = False

    @property
    def name(self) -> str:
        """Return the name of the audit policy."""
        status = "ok" if self.is_success else "fail"
        return f"{self.action}_{self.object_class}_{status}"

    def as_dict(self) -> dict:
        """Convert the data transfer object to a dictionary."""
        return {
            "name": self.name,
            "is_enabled": self.is_enabled,
            "severity": self.severity,
        }


@dataclass
class AuditPolicyTriggerDTO:
    """Audit policy trigger data transfer object."""

    is_ldap: bool
    is_http: bool
    operation_code: OperationEvent
    object_class: str
    is_operation_success: bool
    additional_info: dict | None = None


@dataclass
class AuditDestinationDTO:
    """Audit destination data transfer object."""

    name: str
    service_type: AuditDestinationServiceType
    is_enabled: bool
    host: str
    port: int
    protocol: AuditDestinationProtocolType
    id: int | None = None


@dataclass
class AuditPolicyDTO:
    """Audit policy data transfer object."""

    id: int
    name: str
    is_enabled: bool
    severity: AuditSeverity


class AuditEvent(ABC):
    """Abstract base class for audit events.

    This class defines the interface for creating and processing audit events.
    It should be extended by specific event types (e.g., LDAP, HTTP).
    """

    @abstractmethod
    def to_redis_message(self) -> dict[str, str]:
        """Convert the event to a dictionary suitable for Redis storage."""

    @classmethod
    @abstractmethod
    def from_redis(cls, redis_data: dict[bytes, bytes]) -> "AuditEvent":
        """Create an AuditEvent instance from Redis dictionary data."""

    def _default_serializer(self, obj: Any) -> Any:
        """Convert various object types to serializable format."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, SecretStr):
            return "********"
        if isinstance(obj, bytes):
            return obj.decode(errors="replace")
        if hasattr(obj, "value"):
            return obj.value
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        try:
            return str(obj)
        except Exception:
            return "[unserializable]"

    def value_to_json_str(self, value: Any) -> str:
        """Convert a value to JSON string representation."""
        try:
            return json.dumps(value, default=self._default_serializer)
        except Exception as e:
            logger.error(f"Failed to serialize value {value}: {e}")
            return str(value)


@dataclass
class RawAuditEvent(AuditEvent):
    """Represent audit event with request, response and connection details."""

    request: dict[str, Any]
    responses: list[dict[str, Any]]
    protocol: str
    request_code: OperationEvent
    context: dict[str, Any]
    username: str
    source_ip: IPv4Address | IPv6Address
    dest_port: int
    timestamp: float = field(
        default_factory=lambda: datetime.now().timestamp(),
    )
    hostname: str = field(default_factory=socket.gethostname)
    http_success_status: bool | None = None
    service_name: str | None = None

    @property
    def is_event_successful(self) -> bool:
        """Determine if the event was successful.

        For HTTP events, uses the http_success_status field.
        For other protocols, checks the last response's result code.
        """
        if self.http_success_status is not None:
            return self.http_success_status

        if not self.responses:
            return True

        return self.responses[-1]["result_code"] == LDAPCodes.SUCCESS

    @classmethod
    def from_redis(cls, redis_data: dict[bytes, bytes]) -> "RawAuditEvent":
        """Create RawAuditEvent instance from Redis dictionary data."""
        decoded_data = {
            key.decode(): value.decode() for key, value in redis_data.items()
        }

        parsed_data = {}
        for key, value in decoded_data.items():
            try:
                parsed_data[key] = json.loads(value)
            except json.JSONDecodeError:
                parsed_data[key] = value

        if "request_code" in parsed_data:
            parsed_data["request_code"] = OperationEvent(
                parsed_data["request_code"],
            )

        if "timestamp" in parsed_data:
            parsed_data["timestamp"] = float(parsed_data["timestamp"])
        if "dest_port" in parsed_data:
            parsed_data["dest_port"] = int(parsed_data["dest_port"])
        if "http_success_status" in parsed_data:
            parsed_data["http_success_status"] = (
                None
                if parsed_data["http_success_status"] == "None"
                else parsed_data["http_success_status"].lower() == "true"
            )

        return cls(**parsed_data)

    def to_redis_message(self) -> dict[str, str]:
        """Transform AuditEvent into dictionary suitable for Redis storage."""
        data = asdict(self)
        data["request_code"] = self.request_code.value
        return {
            key: self.value_to_json_str(value)
            if isinstance(value, dict) or isinstance(value, list)
            else str(value)
            for key, value in data.items()
        }


@dataclass
class NormalizedAuditEvent(AuditEvent):
    """Normalized audit event model."""

    username: str
    source_ip: str
    dest_port: int
    timestamp: float
    hostname: str
    protocol: str
    event_type: str
    severity: str
    policy_id: int
    is_operation_success: bool
    details: dict[str, Any]
    service_name: str | None = None

    def to_redis_message(self) -> dict[str, str]:
        """Convert the normalized event to a dictionary for Redis storage."""
        return {
            key: self.value_to_json_str(value)
            if isinstance(value, dict) or isinstance(value, list)
            else str(value)
            for key, value in asdict(self).items()
        }

    @classmethod
    def from_redis(cls, data: dict[bytes, bytes]) -> "NormalizedAuditEvent":
        """Create an instance from Redis dictionary data."""
        decoded = {}
        for key, value in data.items():
            key_str = key.decode("utf-8")
            try:
                decoded[key_str] = json.loads(value.decode("utf-8"))
            except Exception:
                decoded[key_str] = value.decode("utf-8")

        if "timestamp" in decoded:
            decoded["timestamp"] = float(decoded["timestamp"])
        if "dest_port" in decoded:
            decoded["dest_port"] = int(decoded["dest_port"])
        if "policy_id" in decoded:
            decoded["policy_id"] = int(decoded["policy_id"])
        if "is_operation_success" in decoded:
            val = decoded["is_operation_success"]
            decoded["is_operation_success"] = (
                val if isinstance(val, bool) else val.lower() == "true"
            )
        return cls(**decoded)
