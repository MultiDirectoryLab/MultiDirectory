"""DI Resolver MultiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from functools import partial, wraps
from typing import Callable, TypeVar, get_type_hints

from dishka import AsyncContainer

T = TypeVar("T", bound=Callable)


async def resolve_deps(func: T, container: AsyncContainer) -> T:
    """Provide async dependencies.

    :param T func: Awaitable
    :param AsyncContainer container: IoC container
    :return T: Awaitable
    """
    hints = get_type_hints(func)
    del hints["return"]
    kwargs = {}

    for arg_name, hint in hints.items():
        kwargs[arg_name] = await container.get(hint)

    return wraps(func)(partial(func, **kwargs))  # type: ignore
