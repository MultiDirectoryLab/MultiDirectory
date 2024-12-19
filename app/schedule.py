"""Simple scheduler for tasks."""

import asyncio
from typing import Callable, Coroutine, TypeAlias

import uvloop
from dishka import AsyncContainer, Scope, make_async_container
from loguru import logger

from config import Settings
from extra.scripts.krb_pass_sync import read_and_save_krb_pwds
from extra.scripts.mf_status_monitoring import TASK_INTERVAL, ping_multifactor
from extra.scripts.principal_block_user_sync import principal_block_sync
from extra.scripts.uac_sync import disable_accounts
from ioc import MainProvider, MFACredsProvider, MFAProvider
from ldap_protocol.dependency import resolve_deps

task_type: TypeAlias = Callable[..., Coroutine]

_TASKS: set[tuple[task_type, float]] = {
    (read_and_save_krb_pwds, 1.5),
    (disable_accounts, 600.0),
    (principal_block_sync, 60.0),
    (ping_multifactor, TASK_INTERVAL),
}


async def _schedule(
    task: task_type,
    wait: float,
    container: AsyncContainer,
) -> None:
    """Run task periodically.

    :param Awaitable task: any task
    :param AsyncContainer container: container
    :param float wait: time to wait after execution
    """
    logger.info("Registered: {}", task.__name__)
    while True:
        async with container(scope=Scope.REQUEST) as ctnr:
            handler = await resolve_deps(func=task, container=ctnr)
            await handler()
        await asyncio.sleep(wait)


def scheduler(settings: Settings) -> None:
    """Sript entrypoint."""
    async def runner(settings: Settings) -> None:
        container = make_async_container(
            MainProvider(),
            MFAProvider(),
            MFACredsProvider(),
            context={Settings: settings},
        )

        async with asyncio.TaskGroup() as tg:
            for task, timeout in _TASKS:
                tg.create_task(_schedule(task, timeout, container))

    def _run() -> None:
        uvloop.run(runner(settings))

    try:
        import py_hot_reload
    except ImportError:
        _run()
    else:
        if settings.DEBUG:
            py_hot_reload.run_with_reloader(_run)
        else:
            _run()


__all__ = ["scheduler"]
