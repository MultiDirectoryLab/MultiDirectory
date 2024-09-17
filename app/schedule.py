"""Simple scheduler for tasks."""
import asyncio
from typing import Callable, Coroutine, TypeAlias

import uvloop
from dishka import AsyncContainer, Scope, make_async_container
from extra.scripts.krb_pass_sync import read_and_save_krb_pwds
from extra.scripts.uac_sync import disable_accounts
from loguru import logger

from config import Settings
from ioc import MainProvider
from ldap_protocol.dependency import resolve_deps

task_type: TypeAlias = Callable[..., Coroutine]

TASKS: set[tuple[task_type, float]] = {
    (read_and_save_krb_pwds, 1.5),
    (disable_accounts, 600.0),
}


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


def main() -> None:
    """Sript entrypoint."""
    settings = Settings()

    async def scheduler() -> None:
        nonlocal settings
        container = make_async_container(
            MainProvider(),
            context={Settings: settings})

        async with asyncio.TaskGroup() as tg:
            for task, timeout in TASKS:
                tg.create_task(schedule(task, timeout, container))

    def _run() -> None:
        uvloop.run(scheduler())

    try:
        import py_hot_reload
    except ImportError:
        _run()
    else:
        if settings.DEBUG:
            py_hot_reload.run_with_reloader(_run)
        else:
            _run()


if __name__ == "__main__":
    main()
