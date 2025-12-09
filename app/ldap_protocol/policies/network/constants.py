"""Network policies constants.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import StrEnum


class ProtocolType(StrEnum):
    """Protocol fields."""

    IS_LDAP = "is_ldap"
    IS_HTTP = "is_http"
    IS_KERBEROS = "is_kerberos"
