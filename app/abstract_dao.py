"""Abstract Data Access Object (DAO) interface.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

from enums import ApiPermissionsType

if TYPE_CHECKING:
    from ldap_protocol.permissions_checker import ApiPermissionsChecker

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


class AbstractService(ABC):
    """Abstract Service/Manager base class for nominal typing."""

    @classmethod
    @abstractmethod
    def _usecase_api_permissions(cls) -> dict[str, ApiPermissionsType]: ...

    def __getattribute__(self, name: str) -> Any:
        """Intercept attribute access."""
        attr = super().__getattribute__(name)
        if not callable(attr) or name.startswith("_"):
            return attr

        if hasattr(self, "_perm_check") and (
            permission := self._usecase_api_permissions().get(name)
        ):
            return self._perm_check.wrap_use_case(permission, attr)
        return attr

    def set_permissions_checker(
        self,
        perm_check: "ApiPermissionsChecker",
    ) -> None:
        """Set permissions checker.

        :param object perm_check: permissions checker
        :return: None
        """
        self._perm_check = perm_check
