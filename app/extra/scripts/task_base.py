"""Task utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from __future__ import annotations

from functools import wraps
from typing import Any, Awaitable, Callable, Coroutine, Generic, TypeVar

from redis.asyncio import Redis

T = TypeVar("T", bound=Callable[..., Awaitable | Coroutine])


class Task(Generic[T]):
    """Task."""

    def __init__(
        self,
        f: T,
        repeat: float,
        one_time: bool,
        global_: bool,
    ) -> None:
        """Init.

        :param T f: function
        :param int repeat: repeat time
        :param bool one_time: flag to run task only once
        :param bool global_: flag to run task in lock mode
        """
        self.f = f
        self.repeat = repeat
        self.one_time = one_time
        self.global_ = global_

    async def __call__(self, storage: Redis) -> None:
        """Call."""
        if self.global_:
            async with storage.lock(self.f.__name__):
                await self.f()
        else:
            await self.f()


def task_metadata(
    repeat: float,
    one_time: bool = False,
    global_: bool = False,
) -> Callable[[T], Task[T]]:
    """Decorate a Task."""
    def decorator(f: T) -> Task[T]:
        @wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Task[T]:
            return Task(f, repeat, one_time, global_)
        return wrapper
    return decorator
