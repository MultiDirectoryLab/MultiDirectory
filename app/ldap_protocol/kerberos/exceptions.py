"""Common business exceptions for all service classes in the project.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum

from errors import BaseDomainException, ErrorStatusCodes


class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    KERBEROS_BASE_DN_NOT_FOUND_ERROR = 1
    KERBEROS_CONFLICT_ERROR = 2
    KERBEROS_NOT_FOUND_ERROR = 3
    KERBEROS_DEPENDENCY_ERROR = 4
    KERBEROS_UNAVAILABLE_ERROR = 5
    KERBEROS_API_ERROR = 6
    KERBEROS_API_CONFLICT_ERROR = 7
    KERBEROS_API_NOT_FOUND_ERROR = 8
    KERBEROS_API_DEPENDENCY_ERROR = 9
    KERBEROS_API_UNAVAILABLE_ERROR = 10
    KERBEROS_API_SETUP_CONFIGS_ERROR = 11
    KERBEROS_API_SETUP_STASH_ERROR = 12
    KERBEROS_API_SETUP_TREE_ERROR = 13
    KERBEROS_API_PRINCIPAL_NOT_FOUND_ERROR = 14
    KERBEROS_API_ADD_PRINCIPAL_ERROR = 15
    KERBEROS_API_GET_PRINCIPAL_ERROR = 16
    KERBEROS_API_DELETE_PRINCIPAL_ERROR = 17
    KERBEROS_API_CHANGE_PASSWORD_ERROR = 18
    KERBEROS_API_RENAME_PRINCIPAL_ERROR = 19
    KERBEROS_API_LOCK_PRINCIPAL_ERROR = 20
    KERBEROS_API_FORCE_PASSWORD_CHANGE_ERROR = 21
    KERBEROS_API_STATUS_NOT_FOUND_ERROR = 22
    KERBEROS_API_CONNECTION_ERROR = 23


class KerberosError(BaseDomainException):
    """Base exception for authentication kerberos-related errors."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR
    status_code = ErrorStatusCodes.BAD_REQUEST


class KerberosConflictError(KerberosError):
    """Raised when a conflict occurs."""

    code = ErrorCodes.KERBEROS_CONFLICT_ERROR


class KerberosNotFoundError(KerberosError):
    """Raised when a resource is not found."""

    code = ErrorCodes.KERBEROS_NOT_FOUND_ERROR


class KerberosDependencyError(KerberosError):
    """Raised when a dependency fails."""

    code = ErrorCodes.KERBEROS_DEPENDENCY_ERROR


class KerberosUnavailableError(KerberosError):
    """Raised when the service is unavailable."""

    code = ErrorCodes.KERBEROS_UNAVAILABLE_ERROR


class KerberosBaseDnNotFoundError(KerberosError):
    """Raised when no base DN is found in the LDAP directory."""

    code = ErrorCodes.KERBEROS_BASE_DN_NOT_FOUND_ERROR


class KRBAPIError(KerberosError):
    """API Error."""


class KRBAPIConflictError(KRBAPIError):
    """Conflict error."""

    code = ErrorCodes.KERBEROS_API_CONFLICT_ERROR


class KRBAPISetupConfigsError(KRBAPIError):
    """Setup configs error."""

    code = ErrorCodes.KERBEROS_API_SETUP_CONFIGS_ERROR


class KRBAPISetupStashError(KRBAPIError):
    """Setup stash error."""

    code = ErrorCodes.KERBEROS_API_SETUP_STASH_ERROR


class KRBAPISetupTreeError(KRBAPIError):
    """Setup tree error."""

    code = ErrorCodes.KERBEROS_API_SETUP_TREE_ERROR


class KRBAPIPrincipalNotFoundError(KRBAPIError):
    """Principal not found error."""

    code = ErrorCodes.KERBEROS_API_PRINCIPAL_NOT_FOUND_ERROR


class KRBAPIAddPrincipalError(KRBAPIError):
    """Add principal error."""

    code = ErrorCodes.KERBEROS_API_ADD_PRINCIPAL_ERROR


class KRBAPIGetPrincipalError(KRBAPIError):
    """Get principal error."""

    code = ErrorCodes.KERBEROS_API_GET_PRINCIPAL_ERROR


class KRBAPIDeletePrincipalError(KRBAPIError):
    """Delete principal error."""

    code = ErrorCodes.KERBEROS_API_DELETE_PRINCIPAL_ERROR


class KRBAPIChangePasswordError(KRBAPIError):
    """Change password error."""

    code = ErrorCodes.KERBEROS_API_CHANGE_PASSWORD_ERROR


class KRBAPIRenamePrincipalError(KRBAPIError):
    """Rename principal error."""

    code = ErrorCodes.KERBEROS_API_RENAME_PRINCIPAL_ERROR


class KRBAPILockPrincipalError(KRBAPIError):
    """Lock principal error."""

    code = ErrorCodes.KERBEROS_API_LOCK_PRINCIPAL_ERROR


class KRBAPIForcePasswordChangeError(KRBAPIError):
    """Force password change error."""

    code = ErrorCodes.KERBEROS_API_FORCE_PASSWORD_CHANGE_ERROR


class KRBAPIStatusNotFoundError(KRBAPIError):
    """Status not found error."""

    code = ErrorCodes.KERBEROS_API_STATUS_NOT_FOUND_ERROR


class KRBAPIConnectionError(KRBAPIError):
    """Connection error."""

    code = ErrorCodes.KERBEROS_API_CONNECTION_ERROR
