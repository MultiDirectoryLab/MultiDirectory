"""Data classes for role management.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from datetime import datetime

from enums import AceType, AuthorizationRules, RoleScope
from ldap_protocol.utils.const import GRANT_DN_STRING


@dataclass
class AccessControlEntryDTO:
    """Access control entry data transfer object."""

    role_id: int
    ace_type: AceType
    scope: RoleScope
    base_dn: GRANT_DN_STRING
    is_allow: bool
    attribute_type_id: int | None
    entity_type_id: int | None

    id: int | None = None
    role_name: str | None = None

    def get_id(self) -> int:
        if self.id is None:
            raise ValueError("Non read model value")
        return self.id


@dataclass
class RoleDTO:
    """Role data transfer object."""

    name: str
    groups: list[str]
    creator_upn: str | None
    is_system: bool

    id: int | None = None
    created_at: datetime | None = None
    permissions: AuthorizationRules = AuthorizationRules(0)
    access_control_entries: list[AccessControlEntryDTO] | None = None

    def get_id(self) -> int:
        if self.id is None:
            raise ValueError("Non read model value")
        return self.id
