"""Audit redis adapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import json
import socket
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field, SecretStr
from redis.asyncio import Redis

from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.objects import OperationEvent


class AuditEvent(BaseModel):
    """Represent audit event with request, response and connection details."""

    request: dict[str, Any]
    responses: list[dict[str, Any]]
    protocol: str
    request_code: OperationEvent
    context: dict[str, Any]
    username: str
    source_ip: IPv4Address | IPv6Address
    dest_port: int = Field(..., gt=0, lt=65536)
    timestamp: float = Field(
        default_factory=lambda: datetime.now().timestamp(),
    )
    hostname: str = Field(default_factory=socket.gethostname)
    http_success_status: bool | None = None
    service_name: str | None = None

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
    def from_redis(cls, redis_data: dict[bytes, bytes]) -> "AuditEvent":
        """Create AuditEvent instance from Redis dictionary data."""
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

    def to_redis_message(self) -> dict[str, str]:
        """Transform AuditEvent into dictionary suitable for Redis storage."""
        data = self.model_dump()
        data["request_code"] = self.request_code.value
        return {
            key: json.dumps(value, default=self._default_serializer)
            if isinstance(value, dict) or isinstance(value, list)
            else str(value)
            for key, value in data.items()
        }


class AuditRedisAdapter:
    """Adapter for managing audit events in Redis streams."""

    _client: Redis
    IS_PROC_EVENT_KEY: str = "is_proc_events"

    def __init__(self, redis: Redis) -> None:
        """Initialize Redis client for audit event operations."""
        self._client = redis

    async def is_event_processing_enabled(self, request_code: int) -> bool:
        """Check whether event processing is enabled for request type."""
        if request_code == OperationEvent.SEARCH:
            return False

        data = await self._client.get(self.IS_PROC_EVENT_KEY)
        return data is not None and int(data) == 1

    async def enable_event_processing(self) -> None:
        """Enable processing of audit events in Redis."""
        await self._client.set(self.IS_PROC_EVENT_KEY, 1)

    async def disable_event_processing(self) -> None:
        """Disable processing of audit events in Redis."""
        await self._client.set(self.IS_PROC_EVENT_KEY, 0)

    async def add_audit_event(
        self,
        stream_name: str,
        event: "AuditEvent",
    ) -> None:
        """Add audit event to specified Redis stream."""
        await self._client.xadd(stream_name, event.to_redis_message())  # type: ignore

    async def create_consumer_group(
        self,
        stream_name: str,
        group_name: str,
        last_id: str = "0",
    ) -> None:
        """Create consumer group for reading events from Redis stream."""
        try:
            await self._client.xgroup_create(
                stream_name,
                group_name,
                last_id,
                mkstream=True,
            )
        except Exception as e:
            self._handle_group_creation_error(e, group_name)

    async def read_events(
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        count: int = 10,
        block: int | None = None,
    ) -> list[tuple[str, list[tuple[str, dict[bytes, bytes]]]]]:
        """Read batch of events from Redis stream using consumer group."""
        return await self._client.xreadgroup(
            group_name,
            consumer_name,
            {stream_name: ">"},
            count=count,
            block=block,
        )

    async def delete_event(
        self,
        stream_name: str,
        group_name: str,
        event_id: str,
    ) -> None:
        """Remove it from Redis stream."""
        await self._client.xack(stream_name, group_name, event_id)
        await self._client.xdel(stream_name, event_id)

    def _handle_group_creation_error(
        self,
        error: Exception,
        group_name: str,
    ) -> None:
        """Handle errors occurring during consumer group creation."""
        if "BUSYGROUP" in str(error):
            logger.critical(f"Consumer group {group_name} already exists.")
        else:
            raise error
