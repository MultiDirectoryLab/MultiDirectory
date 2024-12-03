"""Redis.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


from abc import ABC, abstractmethod
from typing import Any

from redis import Redis


class AbstractRedisClient(ABC):
    """Stub client for Redis."""

    _client: Redis
    redis_url: str

    def __init__(self, redis_url: str) -> None:
        """Initialize the Redis client.

        :param redis_url: URL for connecting to Redis.
        """
        self.redis_url = redis_url

    async def connect(self) -> None:
        """Establish a connection to Redis."""
        self._client = Redis.from_url(self.redis_url)

    async def disconnect(self) -> None:
        """Close the connection to Redis."""
        if self._client:
            await self._client.close()

    @abstractmethod
    async def get_value(self, key: str) -> Any | None:
        """Retrieve a value from Redis by key."""
        pass

    @abstractmethod
    async def set_value(
        self, key: str,
        value: Any,
        expire: int | None = None,
    ) -> None:
        """Set a value in Redis with an optional expiration time."""
        pass

    @abstractmethod
    async def delete_value(self, key: str) -> None:
        """Delete a key from Redis."""
        pass

    @abstractmethod
    async def add_to_stream(
        self, stream_name: str,
        message: dict[str, Any],
    ) -> str:
        """Add a message to a stream.

        :param stream_name: Name of the stream.
        :param message: Message as a dictionary.
        :return: Message ID of the added entry.
        """
        pass

    @abstractmethod
    async def read_from_stream(
        self,
        stream_name: str,
        last_id: str = "0",
        count: int = 10,
        block: int | None = None,
    ) -> list[tuple[str, list[tuple[str, dict[bytes, bytes]]]]]:
        """Read messages from a stream.

        :param stream_name: Name of the stream.
        :param last_id: The last processed message ID (default: "0").
        :param count: Max number of messages to fetch.
        :param block: Block timeout in milliseconds (default: None).
        :return: List of streams with messages.
        """
        pass

    @abstractmethod
    async def create_consumer_group(
        self, stream_name: str, group_name: str, last_id: str = "0",
    ) -> None:
        """Create a consumer group for a stream.

        :param stream_name: Name of the stream.
        :param group_name: Name of the consumer group.
        :param last_id: Starting ID for the group.
        """
        pass

    @abstractmethod
    async def read_from_group(
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        count: int = 10,
        block: int | None = None,
    ) -> list[tuple[str, list[tuple[str, dict[bytes, bytes]]]]]:
        """Read messages from a stream as part of a consumer group.

        :param stream_name: Name of the stream.
        :param group_name: Name of the consumer group.
        :param consumer_name: Name of the consumer.
        :param count: Max number of messages to fetch.
        :param block: Block timeout in milliseconds (default: None).
        :return: List of streams with messages.
        """

    @abstractmethod
    async def ack_message(
        self, stream_name: str,
        group_name: str,
        message_id: str,
    ) -> None:
        """Acknowledge a message in a consumer group.

        :param stream_name: Name of the stream.
        :param group_name: Name of the consumer group.
        :param message_id: ID of the message to acknowledge.
        """
        pass


class RedisClient(AbstractRedisClient):
    """Redis client."""

    async def get_value(self, key: str) -> Any | None:  # noqa: D102
        if not self._client:
            raise ConnectionError("Redis client is not connected.")
        value = await self._client.get(key)
        return value.decode('utf-8') if value else None

    async def set_value(  # noqa: D102
        self, key: str,
        value: Any,
        expire: int | None = None,
    ) -> None:
        if not self._client:
            raise ConnectionError("Redis client is not connected.")

        await self._client.set(key, value, ex=expire)

    async def delete_value(self, key: str) -> None:  # noqa: D102
        if not self._client:
            raise ConnectionError("Redis client is not connected.")

        await self._client.delete(key)

    async def add_to_stream(  # noqa: D102
        self, stream_name: str,
        message: dict[str, Any],
    ) -> str:
        if not self._client:
            raise ConnectionError("Redis client is not connected.")

        return await self._client.xadd(stream_name, message)  # type: ignore

    async def read_from_stream(  # noqa: D102
        self,
        stream_name: str,
        last_id: str = "0",
        count: int = 10,
        block: int | None = None,
    ) -> list[tuple[str, list[tuple[str, dict[bytes, bytes]]]]]:
        if not self._client:
            raise ConnectionError("Redis client is not connected.")

        return await self._client.xread(
            {stream_name: last_id},
            count=count,
            block=block,
        )

    async def create_consumer_group(  # noqa: D102
        self, stream_name: str, group_name: str, last_id: str = "0",
    ) -> None:
        if not self._client:
            raise ConnectionError("Redis client is not connected.")
        try:
            await self._client.xgroup_create(stream_name, group_name, last_id)
        except Exception as e:
            if "BUSYGROUP" in str(e):
                print(f"Consumer group {group_name} already exists.")
            else:
                raise

    async def read_from_group(  # noqa: D102
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        count: int = 10,
        block: int | None = None,
    ) -> list[tuple[str, list[tuple[str, dict[bytes, bytes]]]]]:
        if not self._client:
            raise ConnectionError("Redis client is not connected.")
        return await self._client.xreadgroup(
            group_name,
            consumer_name,
            {stream_name: ">"},
            count=count,
            block=block,
        )

    async def ack_message(  # noqa: D102
        self, stream_name: str,
        group_name: str,
        message_id: str,
    ) -> None:
        if not self._client:
            raise ConnectionError("Redis client is not connected.")

        await self._client.xack(stream_name, group_name, message_id)
