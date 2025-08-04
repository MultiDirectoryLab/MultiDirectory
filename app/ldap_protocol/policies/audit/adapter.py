"""Audit redis adapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from loguru import logger
from redis.asyncio import Redis

from ldap_protocol.objects import OperationEvent

from .dataclasses import AuditEvent


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
        event: AuditEvent,
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
