"""Audit redis adapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from loguru import logger
from redis.asyncio import Redis

from .dataclasses import AuditEvent

type RedisEvents = list[list[tuple[str, list[tuple[str, dict[bytes, bytes]]]]]]
TEvent = TypeVar("TEvent", bound=RedisEvents, covariant=True)


class AuditABCAdapter(ABC, Generic[TEvent]):
    """Abstract base class for audit adapters."""

    @property
    @abstractmethod
    def _client(self) -> Any:
        """Redis client for audit operations."""

    @abstractmethod
    async def send_event(self, event: AuditEvent) -> None:
        """Send audit event to the adapter."""

    @abstractmethod
    async def read_events(self) -> TEvent:
        """Read audit events from the adapter."""

    @abstractmethod
    async def delete_event(self, event_id: str) -> None:
        """Delete an event from the adapter."""

    @abstractmethod
    async def setup_reading(self) -> None:
        """Set up read events from the adapter."""

    @abstractmethod
    async def get_processing_status(self) -> bool:
        """Check whether event processing is enabled."""

    @abstractmethod
    async def update_processing_status(self, status: bool) -> None:
        """Update the processing status of audit events."""


class AuditRedisAdapter(AuditABCAdapter[RedisEvents]):
    """Adapter for managing audit events in Redis streams."""

    _client: Redis
    _stream_name: str
    _group_name: str
    _consumer_name: str
    _is_event_processing_enabled_key: str

    def __init__(
        self,
        redis: Redis,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        is_event_processing_enabled_key: str,
    ) -> None:
        """Initialize Redis client for audit event operations."""
        self._client = redis
        self._stream_name = stream_name
        self._group_name = group_name
        self._consumer_name = consumer_name
        self._is_event_processing_enabled_key = is_event_processing_enabled_key

    async def get_processing_status(self) -> bool:
        data = await self._client.get(self._is_event_processing_enabled_key)
        return data is not None and int(data) == 1

    async def update_processing_status(self, status: bool) -> None:
        """Update the processing status of audit events."""
        await self._client.set(
            self._is_event_processing_enabled_key,
            int(status),
        )

    async def send_event(self, event: AuditEvent) -> None:
        await self._client.xadd(self._stream_name, event.to_redis_message())  # type: ignore

    async def read_events(self) -> RedisEvents:
        return await self._client.xreadgroup(
            self._group_name,
            self._consumer_name,
            {self._stream_name: ">"},
            count=10,
            block=5000,
        )

    async def setup_reading(self) -> None:
        try:
            await self._client.xgroup_create(
                self._stream_name,
                self._group_name,
                "0",
                mkstream=True,
            )
        except Exception as e:
            self._handle_group_creation_error(e, self._group_name)

    async def delete_event(self, event_id: str) -> None:
        await self._client.xack(self._stream_name, self._group_name, event_id)
        await self._client.xdel(self._stream_name, event_id)

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
