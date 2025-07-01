"""Common business exceptions for all service classes in the project."""


class NotFoundError(Exception):
    """Raised when a resource is not found."""


class ForbiddenError(Exception):
    """Raised when an action is forbidden."""


class PolicyError(Exception):
    """Raised for policy-specific errors."""


class MFAError(Exception):
    """Raised for MFA-specific errors."""


class KerberosError(Exception):
    """Raised for Kerberos-related errors."""


class DNSError(Exception):
    """Raised for DNS-related errors."""


class UnauthorizedError(Exception):
    """Raised when authentication fails."""


class KerberosConflictError(KerberosError):
    """Raised when a conflict occurs (HTTP 409)."""


class KerberosNotFoundError(KerberosError):
    """Raised when a resource is not found (HTTP 404)."""


class KerberosDependencyError(KerberosError):
    """Raised when a dependency fails (HTTP 424)."""


class KerberosUnavailableError(KerberosError):
    """Raised when the service is unavailable (HTTP 503)."""


class KerberosInternalError(KerberosError):
    """Raised for internal errors (HTTP 500)."""
