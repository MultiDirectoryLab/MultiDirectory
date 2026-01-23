"""Async cache implementation."""

import time
from functools import wraps
from typing import Callable, Generic, TypeVar

from entities import Directory

T = TypeVar("T")
DEFAULT_CACHE_TIME = 5 * 60  # 5 minutes


class AsyncTTLCache(Generic[T]):
    def __init__(self, ttl: int | None = DEFAULT_CACHE_TIME) -> None:
        self._ttl = ttl
        self._value: T | None = None
        self._expires_at: float | None = None

    def clear(self) -> None:
        self._value = None
        self._expires_at = None

    def __call__(self, func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: tuple, **kwargs: dict) -> T:
            if self._value is not None:
                if not self._expires_at or self._expires_at > time.monotonic():
                    return self._value
                self.clear()

            result = await func(*args, **kwargs)

            self._value = result
            self._expires_at = (
                time.monotonic() + self._ttl if self._ttl else None
            )

            return result

        return wrapper


base_directories_cache = AsyncTTLCache[list[Directory]]()
