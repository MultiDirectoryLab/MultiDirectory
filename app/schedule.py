"""Simple scheduler for tasks."""

import asyncio
from typing import Callable, Coroutine

import uvloop
from dishka import AsyncContainer, Scope, make_async_container
from loguru import logger

from config import Settings
from extra.scripts.check_ldap_principal import check_ldap_principal
from extra.scripts.principal_block_user_sync import principal_block_sync
from extra.scripts.uac_sync import disable_accounts
from extra.scripts.update_krb5_config import update_krb5_config
from ioc import MainProvider
from ldap_protocol.dependency import resolve_deps
from ldap_protocol.ldap_schema.entry_crud import attach_entry_to_directories

type task_type = Callable[..., Coroutine]

_TASKS: set[tuple[task_type, float]] = {
    (disable_accounts, 600.0),
    (principal_block_sync, 60.0),
    (check_ldap_principal, -1.0),
    (update_krb5_config, -1.0),
    (attach_entry_to_directories, 900.0),
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

        # NOTE: one-time tasks
        if wait < 0.0:
            break

        await asyncio.sleep(wait)


def scheduler(settings: Settings) -> None:
    """Sript entrypoint."""

    async def runner(settings: Settings) -> None:
        container = make_async_container(
            MainProvider(),
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
