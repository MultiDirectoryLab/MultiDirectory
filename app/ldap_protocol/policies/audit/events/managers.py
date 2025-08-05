"""Audit managers.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import itertools
from abc import ABC, abstractmethod
from typing import Generic, TypeVar, get_args

from loguru import logger
from redis.asyncio import Redis

from .dataclasses import (
    NormalizedAuditEvent,
    NormalizedAuditEventRedis,
    RawAuditEvent,
    RawAuditEventRedis,
)

T = TypeVar("T", bound=NormalizedAuditEvent | RawAuditEvent)
Event = TypeVar(
    "Event",
    bound=NormalizedAuditEventRedis | RawAuditEventRedis,
)


class AbstractAuditManager(ABC, Generic[T]):
    """Abstract base class for audit adapters."""

    @property
    def _class(self) -> type[T]:
        return get_args(self.__orig_class__)[0]  # type: ignore

    @abstractmethod
    async def send_event(self, event: T) -> None:
        """Send audit event to the adapter."""

    @abstractmethod
    async def read_events(self) -> list[T]:
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


class AuditRedisManager(
    AbstractAuditManager[Event],
):
    """Adapter for managing audit events in Redis streams."""

    def __init__(
        self,
        client: Redis,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        process_enabled_key: str,
    ) -> None:
        """Initialize Redis client for audit event operations."""
        self._client = client
        self._stream_name = stream_name
        self._group_name = group_name
        self._consumer_name = consumer_name
        self._process_enabled_key = process_enabled_key

    async def get_processing_status(self) -> bool:
        data = await self._client.get(self._process_enabled_key)
        return data is not None and int(data) == 1

    async def update_processing_status(self, status: bool) -> None:
        """Update the processing status of audit events."""
        await self._client.set(
            self._process_enabled_key,
            int(status),
        )

    async def send_event(self, event: Event) -> None:
        await self._client.xadd(self._stream_name, event.to_queue())

    async def read_events(self) -> list[Event]:
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

        return [self._class.from_queue(event) for event in events]  # type: ignore

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


RawAuditManager = AuditRedisManager[RawAuditEventRedis]
NormalizedAuditManager = AuditRedisManager[NormalizedAuditEventRedis]
