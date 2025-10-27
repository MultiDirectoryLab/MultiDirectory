"""Network policies DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network

from enums import MFAFlags


@dataclass
class NetworkPolicyDTO:
    """Network policy DTO."""

    mfa_status: MFAFlags
    id: int | None = None
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
