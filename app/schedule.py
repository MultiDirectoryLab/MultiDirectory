"""Simple scheduler for tasks."""
import asyncio
from typing import Callable, Coroutine, TypeAlias

import uvloop
from dishka import AsyncContainer, Scope, make_async_container
from extra.scripts.krb_pass_sync import read_and_save_krb_pwds
from loguru import logger

from config import Settings
from ioc import MainProvider
from ldap_protocol.dependency import resolve_deps

task_type: TypeAlias = Callable[..., Coroutine]

TASKS: tuple[tuple[task_type, float]] = (
    (read_and_save_krb_pwds, 1.5),
)


async def schedule(
    task: task_type,
    wait: float,
    container: AsyncContainer,
) -> None:
    """Run task periodically.

    :param Awaitable task: any task
    :param AsyncContainer container: container
    :param float wait: time to wait after execution
    """
    logger.info('Registered: {}', task.__name__)
    while True:
        async with container(scope=Scope.REQUEST) as ctnr:
            handler = await resolve_deps(func=task, container=ctnr)
            await handler()
        await asyncio.sleep(wait)


async def main() -> None:
    """Sript entrypoint."""
    container = make_async_container(
        MainProvider(),
        context={Settings: Settings()})

    async with asyncio.TaskGroup() as tg:
        for task, timeout in TASKS:
            tg.create_task(schedule(task, timeout, container))


if __name__ == "__main__":
    uvloop.run(main())