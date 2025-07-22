"""Exception classes for multi-factor authentication (MFA) related errors.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class MFAIdentityError(Exception):
    """Base exception for MFA identity-related errors."""


class ForbiddenError(MFAIdentityError):
    """Raised when an action is forbidden."""


class MFARequiredError(MFAIdentityError):
    """Raised when MFA is required for authentication."""


class MFAError(MFAIdentityError):
    """Raised for general MFA errors."""


class MFATokenError(MFAIdentityError):
    """Raised when an MFA token is invalid or missing."""


class MissingMFACredentialsError(MFAIdentityError):
    """Raised when MFA credentials are missing or not configured."""


class InvalidCredentialsError(MFAIdentityError):
    """Raised when provided credentials are invalid."""


class NetworkPolicyError(MFAIdentityError):
    """Raised when a network policy violation occurs."""


class NotFoundError(MFAIdentityError):
    """Raised when a required resource is not found user, MFA config."""
