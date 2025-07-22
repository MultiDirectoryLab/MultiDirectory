"""Common business exceptions for all service classes in the project.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class KerberosError(Exception):
    """Base exception for authentication kerberos-related errors."""


class KerberosConflictError(KerberosError):
    """Raised when a conflict occurs."""


class KerberosNotFoundError(KerberosError):
    """Raised when a resource is not found."""


class KerberosDependencyError(KerberosError):
    """Raised when a dependency fails."""


class KerberosUnavailableError(KerberosError):
    """Raised when the service is unavailable."""


class KerberosBaseDnNotFoundError(KerberosError):
    """Raised when no base DN is found in the LDAP directory."""
