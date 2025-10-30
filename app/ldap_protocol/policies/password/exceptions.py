"""Password Policies exceptions module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""


class PasswordPolicyBaseError(Exception):
    """Base exception class for Password Policy service errors."""


class PasswordPolicyAlreadyExistsError(PasswordPolicyBaseError):
    """Exception raised when a Password Policy already exists."""


class PasswordPolicyNotFoundError(PasswordPolicyBaseError):
    """Exception raised when a Password Policy not found."""


class PasswordPolicyDirIsNotUserError(PasswordPolicyBaseError):
    """Exception raised when the directory is not a user."""


class PasswordPolicyBaseDnNotFoundError(PasswordPolicyBaseError):
    """Exception raised when a Base DN not found."""


class PasswordPolicyCantChangeDefaultDomainError(PasswordPolicyBaseError):
    """Cannot change the name of the default domain Password Policy."""


class PasswordPolicyCantDeleteError(PasswordPolicyBaseError):
    """Cannot delete the last Password Policy."""


class PasswordPolicyUpdatePrioritiesError(PasswordPolicyBaseError):
    """Not all priorities set."""


class PasswordPolicyPriorityError(PasswordPolicyBaseError):
    """Exception raised when there is a priority error."""


class PasswordPolicyAgeDaysError(PasswordPolicyBaseError):
    """Exception raised when the age days are invalid."""
