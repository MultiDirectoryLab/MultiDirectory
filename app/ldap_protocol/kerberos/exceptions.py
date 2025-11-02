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


class KRBAPIError(Exception):
    """API Error."""


class KRBAPIConflictError(KRBAPIError):
    """Conflict error."""


class KRBAPISetupConfigsError(KRBAPIError):
    """Setup configs error."""


class KRBAPISetupStashError(KRBAPIError):
    """Setup stash error."""


class KRBAPISetupTreeError(KRBAPIError):
    """Setup tree error."""


class KRBAPIPrincipalNotFoundError(KRBAPIError):
    """Principal not found error."""


class KRBAPIAddPrincipalError(KRBAPIError):
    """Add principal error."""


class KRBAPIGetPrincipalError(KRBAPIError):
    """Get principal error."""


class KRBAPIDeletePrincipalError(KRBAPIError):
    """Delete principal error."""


class KRBAPIChangePasswordError(KRBAPIError):
    """Change password error."""


class KRBAPIRenamePrincipalError(KRBAPIError):
    """Rename principal error."""


class KRBAPILockPrincipalError(KRBAPIError):
    """Lock principal error."""


class KRBAPIForcePasswordChangeError(KRBAPIError):
    """Force password change error."""


class KRBAPIStatusNotFoundError(KRBAPIError):
    """Status not found error."""


class KRBAPIConnectionError(KRBAPIError):
    """Connection error."""


print(isinstance(KRBAPIConnectionError(), KRBAPIError))
