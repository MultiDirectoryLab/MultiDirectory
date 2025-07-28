"""API module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .audit.policy_router import audit_router
from .auth.router import auth_router
from .auth.router_mfa import mfa_router
from .auth.router_pwd_policy import pwd_router
from .auth.session_router import session_router
from .ldap_schema.entity_type_router import ldap_schema_router
from .main.dns_router import dns_router
from .main.krb5_router import krb5_router
from .main.router import entry_router
from .network.router import network_router
from .shadow.router import shadow_router

__all__ = [
    "audit_router",
    "auth_router",
    "session_router",
    "network_router",
    "mfa_router",
    "pwd_router",
    "ldap_schema_router",
    "dns_router",
    "krb5_router",
    "entry_router",
    "network_router",
    "shadow_router",
]
