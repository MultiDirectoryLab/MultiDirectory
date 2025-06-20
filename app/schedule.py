"""Simple scheduler for tasks.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from typing import Callable, Coroutine

from dishka import AsyncContainer, Scope
from loguru import logger

from extra.scripts.check_ldap_principal import check_ldap_principal
from extra.scripts.need_to_proc_events import check_events_to_process
from extra.scripts.principal_block_user_sync import principal_block_sync
from extra.scripts.send_events import send_events
from extra.scripts.uac_sync import disable_accounts
from extra.scripts.update_krb5_config import update_krb5_config
from ldap_protocol.dependency import resolve_deps

type task_type = Callable[..., Coroutine]

MAINTENCE_TASKS: set[tuple[task_type, float]] = {
    (disable_accounts, 600.0),
    (principal_block_sync, 60.0),
    (check_ldap_principal, -1.0),
    (update_krb5_config, -1.0),
    (check_events_to_process, 300.0),
}
EVENTS_TASKS: set[tuple[task_type, float]] = {(send_events, 60)}


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
            kwargs = await resolve_deps(func=task, container=ctnr)
            await task(**kwargs)

        # NOTE: one-time tasks
        if wait < 0.0:
            break

        await asyncio.sleep(wait)


__all__ = ["_schedule", "MAINTENCE_TASKS", "EVENTS_TASKS"]
