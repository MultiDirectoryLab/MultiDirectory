"""Base Adapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ParamSpec, Protocol, TypeVar

from abstract_service import AbstractService
from authorization_provider_protocol import AuthorizationProviderProtocol

_P = ParamSpec("_P")
_R = TypeVar("_R")
_T = TypeVar("_T", bound=AbstractService)


class BaseAdapter(Protocol[_T]):
    """Abstract Adapter interface."""

    _service: _T

    def __init__(
        self,
        service: _T,
        perm_checker: AuthorizationProviderProtocol,
    ) -> None:
        """Set service."""
        self._service = service
        self._service.set_permissions_checker(perm_checker)
