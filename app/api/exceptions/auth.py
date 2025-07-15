"""Exception classes for authentication-related errors.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class IdentityError(Exception):
    """Base exception for authentication identity-related errors."""


class UnauthorizedError(IdentityError):
    """Raised when authentication fails due to invalid credentials."""


class AlreadyConfiguredError(IdentityError):
    """Raised when setup is attempted but already performed."""


class ForbiddenError(IdentityError):
    """Raised when access is forbidden due to policy or group membership."""


class LoginFailedError(IdentityError):
    """Raised when login fails for reasons other than invalid credentials."""


class PasswordPolicyError(IdentityError):
    """Raised when a password does not meet policy requirements."""


class UserNotFoundError(IdentityError):
    """Raised when a user is not found in the system."""
