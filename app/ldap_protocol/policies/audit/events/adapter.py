"""Audit redis adapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import itertools
from abc import ABC, abstractmethod
from typing import Generic, NewType, TypeVar

from loguru import logger
from redis.asyncio import Redis

from .dataclasses import AuditEvent, AuditEventRedis

Events = TypeVar("Events", bound=AuditEvent)


class AuditABCAdapter(ABC, Generic[Events]):
    """Abstract base class for audit adapters."""

    @abstractmethod
    async def send_event(self, event: Events) -> None:
        """Send audit event to the adapter."""

    @abstractmethod
    async def read_events(self) -> list[Events]:
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


class AuditRedisAdapter(AuditABCAdapter[AuditEventRedis]):
    """Adapter for managing audit events in Redis streams."""

    def __init__(
        self,
        client: Redis,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        is_event_processing_enabled_key: str,
        _class: type[AuditEventRedis],
    ) -> None:
        """Initialize Redis client for audit event operations."""
        self._client = client
        self._stream_name = stream_name
        self._group_name = group_name
        self._consumer_name = consumer_name
        self._is_event_processing_enabled_key = is_event_processing_enabled_key
        self._class = _class

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
        await self._client.xadd(self._stream_name, event.to_queue())

    async def read_events(self) -> list[AuditEventRedis]:
        data = await self._client.xreadgroup(
            self._group_name,
            self._consumer_name,
            {self._stream_name: ">"},
            count=10,
            block=5000,
        )

        events = itertools.chain.from_iterable(
            event_list for _, event_list in data
        )

        return [self._class.from_queue(event) for event in events]

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
            logger.info(f"Consumer group {group_name} already exists.")
        else:
            raise error


AuditRawAdapter = NewType("AuditRawAdapter", AuditABCAdapter)
AuditNormalizedAdapter = NewType("AuditNormalizedAdapter", AuditABCAdapter)
