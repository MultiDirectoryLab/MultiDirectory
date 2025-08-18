"""Base Adapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from asyncio import iscoroutinefunction
from functools import wraps
from typing import Callable, ParamSpec, Protocol, TypeVar

from fastapi import HTTPException

from abstract_dao import AbstractDAO, AbstractService

_P = ParamSpec("_P")
_R = TypeVar("_R")
_T = TypeVar("_T", bound=AbstractDAO | AbstractService)


class BaseAdapter(Protocol[_T]):
    """Abstract Adapter interface."""

    _exceptions_map: dict[type[Exception], int]
    _service: _T

    def __init__(self, service: _T) -> None:
        """Set service."""
        self._service = service

    def __getattribute__(self, name: str) -> object:
        """Override attribute access to wrap DAO in an async wrapper."""
        attr = super().__getattribute__(name)

        if not callable(attr):
            return attr

        def safecall(func: Callable[_P, _R]) -> Callable[_P, _R]:
            @wraps(func)
            async def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
                try:
                    if iscoroutinefunction(func):
                        retval = await func(*args, **kwargs)
                    else:
                        retval = func(*args, **kwargs)

                except Exception as err:
                    code = self._exceptions_map.get(type(err))

                    if code is None:
                        raise

                    raise HTTPException(
                        status_code=code,
                        detail=str(err),
                    ) from err

                else:
                    return retval

            return wrapper  # type: ignore

        return safecall(attr)
