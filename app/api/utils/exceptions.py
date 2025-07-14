"""Common business exceptions for all service classes in the project."""


class NotFoundError(Exception):
    """Raised when a resource is not found."""


class ForbiddenError(Exception):
    """Raised when an action is forbidden."""


class PolicyError(Exception):
    """Raised for policy-specific errors."""


class KerberosError(Exception):
    """Raised for Kerberos-related errors."""


class DNSError(Exception):
    """Raised for DNS-related errors."""


class UnauthorizedError(Exception):
    """Raised when authentication fails."""


class MissingMFACredentialsError(ForbiddenError):
    """Raised when MFA API credentials are missing."""


class InvalidCredentialsError(ForbiddenError):
    """Raised when user credentials are invalid."""


class MFATokenError(Exception):
    """Raised when MFA token is invalid or user not found for callback."""


class UserNotFoundError(ForbiddenError):
    """Raised when user is not found during password reset."""


class PasswordPolicyError(ForbiddenError):
    """Raised when password does not meet policy requirements."""
