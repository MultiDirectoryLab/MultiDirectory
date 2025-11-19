"""Abstract Service/Manager interface.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from enums import ApiPermissionsType

if TYPE_CHECKING:
    from ldap_protocol.permissions_checker import ApiPermissionsChecker


class AbstractService(ABC):
    """Abstract Service/Manager base class."""

    @classmethod
    @abstractmethod
    def _usecase_api_permissions(cls) -> dict[str, ApiPermissionsType]:
        """Define use case and permission map for access check."""
        ...

    def __getattribute__(self, name: str) -> Any:
        """Intercept attribute access."""
        attr = super().__getattribute__(name)
        if not callable(attr) or name.startswith("_"):
            return attr

        if getattr(self, "_perm_checker", None) and (
            permission := self._usecase_api_permissions().get(name)
        ):
            return self._perm_checker.wrap_use_case(permission, attr)
        return attr

    def set_permissions_checker(
        self,
        perm_checker: "ApiPermissionsChecker",
    ) -> None:
        """Set permissions checker.

        :param object perm_checker: permissions checker
        :return: None
        """
        self._perm_checker = perm_checker
