"""Network policies DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Generic, TypeVar

from enums import MFAFlags

_IdT = TypeVar("_IdT", int, None)


@dataclass
class NetworkPolicyDTO(Generic[_IdT]):
    """Network policy DTO."""

    id: _IdT
    mfa_status: MFAFlags
    name: str = ""
    raw: dict | list = field(default_factory=dict)
    netmasks: list[IPv4Network | IPv4Address] = field(default_factory=list)
    enabled: bool = True
    priority: int = 0
    is_ldap: bool = True
    is_http: bool = True
    is_kerberos: bool = True
    bypass_no_connection: bool = False
    bypass_service_failure: bool = False
    ldap_session_ttl: int = -1
    http_session_ttl: int = 28800
    groups: list[str] = field(default_factory=list)
    mfa_groups: list[str] = field(default_factory=list)


@dataclass
class NetworkPolicyUpdateDTO:
    """Network policy update DTO."""

    id: int
    name: str | None = None
    netmasks: list[IPv4Network | IPv4Address] | None = None
    groups: list[str] | None = None
    mfa_groups: list[str] | None = None
    mfa_status: MFAFlags | None = None
    is_http: bool | None = None
    is_ldap: bool | None = None
    is_kerberos: bool | None = None
    bypass_no_connection: bool | None = None
    bypass_service_failure: bool | None = None
    raw: dict | list | None = None

    @property
    def fields_to_update(self) -> list[str]:
        """Get fields to update."""
        return [
            "name",
            "mfa_status",
            "is_http",
            "is_ldap",
            "is_kerberos",
            "bypass_no_connection",
            "bypass_service_failure",
        ]


@dataclass
class SwapPrioritiesDTO:
    """Swap priorities DTO."""

    priority1: int
    priority2: int
