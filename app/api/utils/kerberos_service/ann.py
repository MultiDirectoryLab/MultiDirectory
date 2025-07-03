"""Type definitions for KerberosService and related helpers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import NamedTuple, TypedDict

from ldap_protocol.ldap_requests import AddRequest


class KerberosAdminDnGroup(NamedTuple):
    """Kerberos admin, services container, and admin group DNs."""

    krbadmin_dn: str
    services_container_dn: str
    krbadmin_group_dn: str


class AddRequests(NamedTuple):
    """AddRequests for Kerberos admin structure: group, services, krb_user."""

    group: AddRequest
    services: AddRequest
    krb_user: AddRequest


class KDCContext(TypedDict):
    """TypedDict for Kerberos KDC configuration context."""

    base_dn: str
    domain: str
    krbadmin: str
    krbgroup: str
    services_container: str
    ldap_uri: str


class LdapRootInfo(NamedTuple):
    """LDAP root DN and domain info."""

    base_dn: str
    domain: str
