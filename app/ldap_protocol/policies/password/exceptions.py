"""Password Policies exceptions module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class PasswordPolicyBaseError(Exception):
    """Base exception class for password policy service errors."""


class PasswordPolicyAlreadyExistsError(PasswordPolicyBaseError):
    """Exception raised when a password policy already exists in the system."""


class PasswordPolicyNotFoundError(PasswordPolicyBaseError):
    """Exception raised when a password policy not found."""
