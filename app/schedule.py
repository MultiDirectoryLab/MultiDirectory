"""Simple scheduler for tasks."""

import asyncio
from typing import Callable, Coroutine, TypeAlias

import uvloop
from dishka import AsyncContainer, Scope, make_async_container
from loguru import logger

from config import Settings
from extra.scripts.check_ldap_principal import check_ldap_principal
from extra.scripts.krb_pass_sync import read_and_save_krb_pwds
from extra.scripts.principal_block_user_sync import principal_block_sync
from extra.scripts.task_base import Task
from extra.scripts.uac_sync import disable_accounts
from extra.scripts.update_krb5_config import update_krb5_config
from ioc import MainProvider
from ldap_protocol.dependency import resolve_deps

_TASKS: set[Task] = {
    read_and_save_krb_pwds,
    disable_accounts,
    principal_block_sync,
    check_ldap_principal,
    update_krb5_config,
}


async def _schedule(
    task: Task,
    wait: float,
    container: AsyncContainer,
) -> None:
    """Run task periodically.

    :param Awaitable task: any task
    :param AsyncContainer container: container
    :param float wait: time to wait after execution
    """
    logger.info("Registered: {}", task.f.__name__)
    while True:
        async with container(scope=Scope.REQUEST) as ctnr:
            handler = await resolve_deps(func=task.f, container=ctnr)
            await handler()

        # NOTE: one-time tasks
        if wait < 0.0:
            break

        await asyncio.sleep(wait)


def scheduler(settings: Settings) -> None:
    """Sript entrypoint."""
    async def runner(settings: Settings) -> None:
        container = make_async_container(
            MainProvider(), context={Settings: settings},
        )

        async with asyncio.TaskGroup() as tg:
            for task in _TASKS:
                tg.create_task(_schedule(task, task.repeat, container))

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
