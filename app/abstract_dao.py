"""Abstract Data Access Object (DAO) interface.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import abstractmethod
from typing import Protocol, TypeVar

_T = TypeVar("_T")
_A = TypeVar("_A", int, str, contravariant=True)


class AbstractDAO(Protocol[_T, _A]):
    """Abstract Data Access Object (DAO) interface."""

    @abstractmethod
    async def get(self, _id: _A) -> _T: ...

    @abstractmethod
    async def get_all(self) -> list[_T]: ...

    @abstractmethod
    async def create(self, dto: _T) -> None: ...

    @abstractmethod
    async def update(self, _id: _A, dto: _T) -> None: ...

    @abstractmethod
    async def delete(self, _id: _A) -> None: ...
