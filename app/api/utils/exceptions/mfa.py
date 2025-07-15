"""Exception classes for multi-factor authentication (MFA) related errors.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class ForbiddenError(Exception):
    """Raised when an action is forbidden."""


class MFARequiredError(Exception):
    """Raised when MFA is required for authentication."""


class MFAError(Exception):
    """Raised for general MFA errors."""


class MFATokenError(Exception):
    """Raised when an MFA token is invalid or missing."""


class MissingMFACredentialsError(Exception):
    """Raised when MFA credentials are missing or not configured."""


class InvalidCredentialsError(Exception):
    """Raised when provided credentials are invalid."""


class NetworkPolicyError(Exception):
    """Raised when a network policy violation occurs."""


class NotFoundError(Exception):
    """Raised when a required resource is not found user, MFA config."""
