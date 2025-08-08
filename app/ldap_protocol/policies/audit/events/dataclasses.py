"""Audit events data classes.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import json
import socket
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Self

from loguru import logger
from pydantic import SecretStr

from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.objects import OperationEvent


class AuditEvent(ABC):
    """Abstract base class for audit events.

    This class defines the interface for creating and processing audit events.
    It should be extended by specific event types (e.g., LDAP, HTTP).
    """

    @classmethod
    @abstractmethod
    def from_queue(cls, queue_data: Any) -> Self:
        """Create an AuditEvent instance from queue data."""

    @abstractmethod
    def to_queue(self) -> dict[Any, Any]:
        """Convert the event to a dictionary suitable for queue storage."""

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
    id: str | None = None

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


class AuditEventRedis(AuditEvent):
    """Abstract base class for audit events stored in Redis."""

    @classmethod
    @abstractmethod
    def from_redis(cls, redis_data: tuple[bytes, dict[bytes, bytes]]) -> Self:
        """Create an AuditEvent instance from Redis dictionary data."""

    @abstractmethod
    def to_redis_message(self) -> dict[str, str]:
        """Convert the event to a dictionary suitable for Redis storage."""

    def to_queue(self) -> dict[Any, Any]:
        """Convert the event to a dictionary suitable for queue storage."""
        return self.to_redis_message()

    @classmethod
    def from_queue(cls, queue_data: Any) -> Self:
        return cls.from_redis(queue_data)


@dataclass
class RawAuditEventRedis(RawAuditEvent, AuditEventRedis):
    """Raw audit event model for Redis storage."""

    @classmethod
    def from_redis(cls, redis_data: tuple[bytes, dict[bytes, bytes]]) -> Self:
        """Create RawAuditEvent instance from Redis dictionary data."""
        redis_id, data = redis_data
        decoded_data = {
            key.decode(): value.decode() for key, value in data.items()
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

        parsed_data["id"] = redis_id.decode("utf-8")

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
    severity: int
    policy_id: int
    is_operation_success: bool
    details: dict[str, Any]
    service_name: str | None = None
    id: str | None = None

    @property
    def syslog_message(self) -> str:
        return f"User {self.username} {self.event_type}"


class NormalizedAuditEventRedis(NormalizedAuditEvent, AuditEventRedis):
    """Normalized audit event model for Redis storage."""

    def to_redis_message(self) -> dict[str, str]:
        """Convert the normalized event to a dictionary for Redis storage."""
        return {
            key: self.value_to_json_str(value)
            if isinstance(value, dict) or isinstance(value, list)
            else str(value)
            for key, value in asdict(self).items()
        }

    @classmethod
    def from_redis(cls, redis_data: tuple[bytes, dict[bytes, bytes]]) -> Self:
        """Create an instance from Redis dictionary data."""
        redis_id, data = redis_data
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
        if "severity" in decoded:
            decoded["policy_id"] = int(decoded["severity"])
        if "is_operation_success" in decoded:
            val = decoded["is_operation_success"]
            decoded["is_operation_success"] = (
                val if isinstance(val, bool) else val.lower() == "true"
            )
        decoded["id"] = redis_id.decode("utf-8")

        return cls(**decoded)
