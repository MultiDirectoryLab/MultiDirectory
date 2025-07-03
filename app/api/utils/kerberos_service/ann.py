"""Type definitions for KerberosService and related helpers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import NamedTuple, TypedDict

from ldap_protocol.ldap_requests import AddRequest


class KerberosAdminDnGroup(NamedTuple):
    krbadmin_dn: str
    services_container_dn: str
    krbadmin_group_dn: str


AddRequests = tuple[AddRequest, AddRequest, AddRequest]


class KDCContext(TypedDict):
    """TypedDict for Kerberos KDC configuration context."""

    base_dn: str
    domain: str
    krbadmin: str
    krbgroup: str
    services_container: str
    ldap_uri: str
