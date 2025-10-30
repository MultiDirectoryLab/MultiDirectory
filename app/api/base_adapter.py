"""Base Adapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from asyncio import iscoroutinefunction
from functools import wraps
from typing import Awaitable, Callable, NoReturn, ParamSpec, Protocol, TypeVar

from errors.catalog import ErrorCatalog
from errors.http_mapper import HttpCodeMapper
from errors.types import HasErrorCode
from fastapi import HTTPException

from abstract_dao import AbstractDAO, AbstractService

_P = ParamSpec("_P")
_R = TypeVar("_R")
_T = TypeVar("_T", bound=AbstractDAO | AbstractService)

_http_mapper = HttpCodeMapper()
_catalog = ErrorCatalog()


class BaseAdapter(Protocol[_T]):
    """Abstract Adapter interface."""

    _service: _T

    def __init__(self, service: _T) -> None:
        """Set service."""
        self._service = service

    def __new__(
        cls,
        *_: tuple,
        **__: dict,
    ) -> "BaseAdapter[_T]":
        """Wrap all public methods with try catch for standardized errors."""
        instance = super().__new__(cls)

        def wrap_sync(func: Callable[_P, _R]) -> Callable[_P, _R]:
            @wraps(func)
            def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
                try:
                    return func(*args, **kwargs)
                except Exception as err:
                    instance._reraise(err)

            return wrapper

        def wrap_async(
            func: Callable[_P, Awaitable[_R]],
        ) -> Callable[_P, Awaitable[_R]]:
            @wraps(func)
            async def awrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
                try:
                    return await func(*args, **kwargs)
                except Exception as err:
                    instance._reraise(err)

            return awrapper

        for name in dir(instance):
            if name.startswith("_"):
                continue

            attr = getattr(instance, name)

            if not callable(attr):
                continue

            if iscoroutinefunction(attr):
                wrapped = wrap_async(attr)
            else:
                wrapped = wrap_sync(attr)

            setattr(instance, name, wrapped)

        return instance

    def _reraise(self, exc: Exception) -> NoReturn:
        """Reraise exception with standardized HTTP status code."""
        if isinstance(exc, HasErrorCode):
            http = _http_mapper.to_http(exc.get_error_code())
            raise HTTPException(status_code=http, detail=str(exc)) from exc

        elif (mapped := _catalog.resolve(exc)) is not None:
            http = _http_mapper.to_http(mapped)
            raise HTTPException(status_code=http, detail=str(exc)) from exc

        code = self._exceptions_map.get(type(exc))

        if code is None:
            raise

        raise HTTPException(
            status_code=code,
            detail=str(exc),
        ) from exc
