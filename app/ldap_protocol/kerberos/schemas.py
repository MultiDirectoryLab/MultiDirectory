"""Type definitions for KerberosService and related helpers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass, field
from typing import Any, Callable

from ldap_protocol.ldap_requests import AddRequest


@dataclass
class KerberosAdminDnGroup:
    """Kerberos admin, services container, and admin group DNs."""

    krbadmin_dn: str
    services_container_dn: str
    krbadmin_group_dn: str


@dataclass
class AddRequests:
    """AddRequests for Kerberos admin structure: group, services, krb_user."""

    group: AddRequest
    services: AddRequest
    krb_user: AddRequest


@dataclass
class KDCContext:
    """Kerberos KDC configuration context."""

    base_dn: str
    domain: str
    krbadmin: str
    krbgroup: str
    services_container: str
    ldap_uri: str


@dataclass
class TaskStruct:
    """Structure for background task: function, args, kwargs."""

    func: Callable[..., Any]
    args: tuple[Any, ...] = field(default_factory=tuple)
    kwargs: dict[str, Any] = field(default_factory=dict)
