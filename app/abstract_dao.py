"""Abstract Data Access Object (DAO) interface.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import abstractmethod
from typing import Protocol, TypeVar

T = TypeVar("T")


class AbstractDAO(Protocol[T]):
    """Abstract Data Access Object (DAO) interface."""

    @abstractmethod
    async def get(self, _id: int) -> T: ...

    @abstractmethod
    async def get_all(self) -> list[T]: ...

    @abstractmethod
    async def create(self, dto: T) -> None: ...

    @abstractmethod
    async def update(self, _id: int, dto: T) -> None: ...

    @abstractmethod
    async def delete(self, _id: int) -> None: ...
