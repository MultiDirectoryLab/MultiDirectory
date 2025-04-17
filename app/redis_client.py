"""Redis.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from loguru import logger
from pydantic import SecretStr
from redis.asyncio import Redis

from ldap_protocol import LDAPRequestMessage
from ldap_protocol.objects import OperationEvent


class AbstractClient(ABC):
    """Abstract client for Redis."""

    _client: Any

    @abstractmethod
    async def send_to_processing(
        self,
        stream_name: str,
        message: dict[str, str],
    ) -> None:
        """Add a message to a stream.

        :param stream_name: Name of the stream.
        :param message: Message as a dictionary.
        """

    @abstractmethod
    async def create_consumer_group(
        self,
        stream_name: str,
        group_name: str,
        last_id: str = "0",
    ) -> None:
        """Create a consumer group for a stream.

        :param stream_name: Name of the stream.
        :param group_name: Name of the consumer group.
        :param last_id: Starting ID for the group.
        """

    @abstractmethod
    async def read(
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        count: int = 10,
        block: int | None = None,
    ) -> list[tuple[str, list[tuple[str, dict[bytes, bytes]]]]]:
        """Read message from redis stream by group.

        :param stream_name: Name of the stream.
        :param group_name: Name of the consumer group.
        :param consumer_name: Name of the consumer.
        :param count: Max number of messages to fetch.
        :param block: Block timeout in milliseconds (default: None).
        :return: List of streams with messages.
        """

    @abstractmethod
    async def remove(self, stream_name: str, message_id: str) -> None:
        """Remove a message from stream.

        :param stream_name: Name of the stream.
        :param group_name: Name of the consumer group.
        :param message_id: ID of the message to acknowledge.
        """

    @abstractmethod
    async def ack_message(
        self,
        stream_name: str,
        group_name: str,
        message_id: str,
    ) -> None:
        """Acknowledge a message in a consumer group.

        :param stream_name: Name of the stream.
        :param group_name: Name of the consumer group.
        :param message_id: ID of the message to acknowledge.
        """


class RedisClient(AbstractClient):
    """Redis client."""

    _client: Redis

    def __init__(self, redis_url: Redis) -> None:
        """Initialize the Redis client.

        :param redis_url: URL for connecting to Redis.
        """
        self._client = redis_url

    async def is_enable_proc_events(self, message: LDAPRequestMessage) -> bool:
        """Check if events need to be processed.

        :return: True if events need to be processed, False otherwise.
        """
        if message.protocol_op == OperationEvent.SEARCH:
            return False

        data = await self._client.get("is_proc_events")
        if data is None:
            return False

        return bool(data) == 1

    async def enable_proc_events(self) -> None:
        """Set events to be processed."""
        await self._client.set("is_proc_events", 1)

    async def disable_proc_events(self) -> None:
        """Set events to not be processed."""
        await self._client.set("is_proc_events", 0)

    async def send_to_processing(
        self,
        stream_name: str,
        message: dict[str, Any],
    ) -> None:
        def custom_serializer(obj: Any) -> Any:
            """Serialize custom objects for json.dumps."""
            if isinstance(obj, SecretStr):
                return "********"

            if hasattr(obj, "isoformat"):
                return obj.isoformat()

            if isinstance(obj, bytes):
                return obj.decode(errors="replace")
            return obj

        message["datetime"] = datetime.now().timestamp()
        for key, value in message.items():
            if isinstance(value, str):
                continue

            message[key] = json.dumps(value, default=custom_serializer)

        return await self._client.xadd(stream_name, message)  # type: ignore

    async def create_consumer_group(
        self,
        stream_name: str,
        group_name: str,
        last_id: str = "0",
    ) -> None:
        try:
            await self._client.xgroup_create(
                stream_name,
                group_name,
                last_id,
                mkstream=True,
            )
        except Exception as e:
            if "BUSYGROUP" in str(e):
                logger.critical(f"Consumer group {group_name} already exists.")
            else:
                raise

    async def read(
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        count: int = 10,
        block: int | None = None,
    ) -> list[tuple[str, list[tuple[str, dict[bytes, bytes]]]]]:
        return await self._client.xreadgroup(
            group_name,
            consumer_name,
            {stream_name: ">"},
            count=count,
            block=block,
        )

    async def ack_message(
        self,
        stream_name: str,
        group_name: str,
        message_id: str,
    ) -> None:
        await self._client.xack(stream_name, group_name, message_id)

    async def remove(
        self,
        stream_name: str,
        message_id: str,
    ) -> None:
        await self._client.xdel(stream_name, message_id)
