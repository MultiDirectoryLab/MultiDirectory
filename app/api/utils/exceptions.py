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
