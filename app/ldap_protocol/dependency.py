"""DI Resolver MiltiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Any, Callable, TypeVar, get_type_hints

from dishka import AsyncContainer
from dishka.exceptions import NoFactoryError

T = TypeVar("T", bound=Callable)


async def resolve_deps(func: T, container: AsyncContainer) -> dict[str, Any]:
    """Provide async dependencies.

    :param T func: Awaitable
    :param AsyncContainer container: IoC container
    :return dict[str, Any]: kwargs for func
    """
    kwargs = {}

    for arg_name, hint in get_type_hints(func).items():
        try:
            kwargs[arg_name] = await container.get(hint)
        except NoFactoryError:
            pass

    return kwargs
