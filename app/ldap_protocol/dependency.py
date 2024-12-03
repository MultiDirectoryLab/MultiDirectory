"""DI Resolver MiltiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Any, Callable, TypeVar, get_type_hints

from dishka import AsyncContainer

T = TypeVar("T", bound=Callable)


async def resolve_deps(func: T, container: AsyncContainer) -> dict[str, Any]:
    """Provide async dependencies.

    :param T func: Awaitable
    :param AsyncContainer container: IoC container
    :return dict[str, Any]: kwargs for func
    """
    hints = get_type_hints(func)
    del hints["return"]
    del hints["for_api"]
    kwargs = {}

    for arg_name, hint in hints.items():
        kwargs[arg_name] = await container.get(hint)

    return kwargs
