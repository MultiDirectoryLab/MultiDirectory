"""Abstract Service/Manager interface.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC
from typing import Any, ClassVar

from authorization_provider_protocol import AuthorizationProviderProtocol
from enums import AuthorizationRules


class AbstractService(ABC):
    """Abstract Service/Manager base class."""

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]]
    _perm_checker: AuthorizationProviderProtocol

    def __getattribute__(self, name: str) -> Any:
        """Intercept attribute access."""
        attr = super().__getattribute__(name)
        if not callable(attr) or name.startswith("_"):
            return attr

        if getattr(self, "_perm_checker", None) and (
            permission := self.PERMISSIONS.get(name)
        ):
            return self._perm_checker.wrap_use_case(permission, attr)
        return attr

    def set_permissions_checker(
        self,
        perm_checker: AuthorizationProviderProtocol,
    ) -> None:
        """Set permissions checker.

        :param object perm_checker: permissions checker
        :return: None
        """
        self._perm_checker = perm_checker
