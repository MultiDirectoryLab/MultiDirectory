"""Type definitions for KerberosService and related helpers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import TypedDict

from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.ldap_responses import AddResponse

BaseDn = tuple[str, str, str]
AddRequests = tuple[AddRequest, AddRequest, AddRequest]
AddResponses = tuple[AddResponse, AddResponse, AddResponse]


class KDCContext(TypedDict):
    """TypedDict for Kerberos KDC configuration context."""

    base_dn: str
    domain: str
    krbadmin: str
    krbgroup: str
    services_container: str
    ldap_uri: str
