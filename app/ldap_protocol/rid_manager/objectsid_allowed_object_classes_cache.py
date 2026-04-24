"""Redis cache for objectSid-related metadata.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import json
from typing import Awaitable, Callable

from ldap_protocol.rid_manager.types import ObjectSidCacheRedisClient


class ObjectSidAllowedObjectClassesCache:
    """Cache for ObjectClass names that allow `objectSid`."""

    _CACHE_KEY = "ldap:objectsid:allowed_object_classes"
    _LOCK_KEY = "lock:ldap:objectsid:allowed_object_classes"
    _LOCK_BLOCKING_TIMEOUT_SECONDS = 5
    _LOCK_LEASE_TIMEOUT_SECONDS = 30

    def __init__(self, redis: ObjectSidCacheRedisClient) -> None:
        self._redis = redis

    def _decode(self, raw: bytes | str) -> set[str] | None:
        if isinstance(raw, bytes | bytearray):
            raw = raw.decode("utf-8", errors="replace")
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            return None

        return {str(v).lower() for v in decoded}

    async def get(self) -> set[str] | None:
        raw = await self._redis.get(self._CACHE_KEY)
        if not raw:
            return None
        return self._decode(raw)

    async def store(self, value: set[str]) -> None:
        normalized = sorted({v.lower() for v in value})
        await self._redis.set(self._CACHE_KEY, json.dumps(normalized))

    async def clear(self) -> None:
        await self._redis.delete(self._CACHE_KEY, self._LOCK_KEY)

    async def get_or_compute(self, compute: Callable[[], Awaitable[set[str]]]) -> set[str]:
        """Read from redis, or compute once under a lock."""
        if cached := await self.get():
            return cached

        lock = self._redis.lock(
            name=self._LOCK_KEY,
            blocking_timeout=self._LOCK_BLOCKING_TIMEOUT_SECONDS,
            timeout=self._LOCK_LEASE_TIMEOUT_SECONDS,
        )
        async with lock:
            if cached2 := await self.get():
                return cached2

            value = await compute()
            normalized = {v.lower() for v in value}
            await self.store(normalized)
            return normalized
