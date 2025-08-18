"""Password Policies exceptions module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class PasswordPolicyAlreadyExistsError(Exception):
    """Exception raised when a password policy already exists in the system."""


class PasswordPolicyNotFoundError(Exception):
    """Exception raised when a password policy not found."""
