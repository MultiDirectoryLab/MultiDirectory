"""Role enums.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, StrEnum


class AceType(IntEnum):
    """ACE types."""

    CREATE_CHILD = 0
    READ = 1
    WRITE = 2
    DELETE = 3
    PASSWORD_MODIFY = 4


class RoleScope(IntEnum):
    """Scope of the role."""

    SELF = 0
    SINGLE_LEVEL = 1
    WHOLE_SUBTREE = 2


class RoleConstants(StrEnum):
    """Role constants."""

    DOMAIN_ADMINS_ROLE_NAME = "Domain Admins Role"
    READ_ONLY_ROLE_NAME = "Read Only Role"
    KERBEROS_ROLE_NAME = "Kerberos Role"

    DOMAIN_ADMINS_GROUP_CN = "cn=domain admins,cn=groups,"
    READONLY_GROUP_CN = "cn=readonly domain controllers,cn=groups,"
    KERBEROS_GROUP_CN = "cn=krbadmin,cn=groups,"
