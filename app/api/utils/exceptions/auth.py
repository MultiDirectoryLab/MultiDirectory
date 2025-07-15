"""Exception classes for authentication-related errors.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class UnauthorizedError(Exception):
    """Raised when authentication fails due to invalid credentials."""


class AlreadyConfiguredError(Exception):
    """Raised when setup is attempted but already performed."""


class ForbiddenError(Exception):
    """Raised when access is forbidden due to policy or group membership."""


class LoginFailedError(Exception):
    """Raised when login fails for reasons other than invalid credentials."""


class PasswordPolicyError(Exception):
    """Raised when a password does not meet policy requirements."""


class UserNotFoundError(Exception):
    """Raised when a user is not found in the system."""
