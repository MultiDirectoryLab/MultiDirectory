"""Password Policies exceptions module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, unique

from api.error_routing import BaseDomainException


@unique
class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    PASSWORD_POLICY_ALREADY_EXISTS_ERROR = 1
    PASSWORD_POLICY_NOT_FOUND_ERROR = 2
    PASSWORD_POLICY_DIR_IS_NOT_USER_ERROR = 3
    PASSWORD_POLICY_BASE_DN_NOT_FOUND_ERROR = 4
    PASSWORD_POLICY_CANT_CHANGE_DEFAULT_DOMAIN_ERROR = 5
    PASSWORD_POLICY_PRIORITY_ERROR = 6
    PASSWORD_POLICY_AGE_DAYS_ERROR = 7

    PASSWORD_BAN_WORD_ERROR = 8
    PASSWORD_BAN_WORD_FILE_HAS_DUPLICATES_ERROR = 9
    PASSWORD_BAN_WORD_TOO_LONG_ERROR = 10
    PASSWORD_BAN_WORD_WRONG_FILE_EXTENSION_ERROR = 11


class PasswordPolicyError(BaseDomainException):
    """Base exception class for Password Policy service errors."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR


class PasswordPolicyAlreadyExistsError(PasswordPolicyError):
    """Exception raised when a Password Policy already exists."""

    code = ErrorCodes.PASSWORD_POLICY_ALREADY_EXISTS_ERROR


class PasswordPolicyNotFoundError(PasswordPolicyError):
    """Exception raised when a Password Policy not found."""

    code = ErrorCodes.PASSWORD_POLICY_NOT_FOUND_ERROR


class PasswordPolicyDirIsNotUserError(PasswordPolicyError):
    """Exception raised when the directory is not a user."""

    code = ErrorCodes.PASSWORD_POLICY_DIR_IS_NOT_USER_ERROR


class PasswordPolicyBaseDnNotFoundError(PasswordPolicyError):
    """Exception raised when a Base DN not found."""

    code = ErrorCodes.PASSWORD_POLICY_BASE_DN_NOT_FOUND_ERROR


class PasswordPolicyCantChangeDefaultDomainError(PasswordPolicyError):
    """Cannot change the name of the default domain Password Policy."""

    code = ErrorCodes.PASSWORD_POLICY_CANT_CHANGE_DEFAULT_DOMAIN_ERROR


class PasswordPolicyPriorityError(PasswordPolicyError):
    """Exception raised when there is a priority error."""

    code = ErrorCodes.PASSWORD_POLICY_PRIORITY_ERROR


class PasswordPolicyAgeDaysError(PasswordPolicyError):
    """Exception raised when the age days are invalid."""

    code = ErrorCodes.PASSWORD_POLICY_AGE_DAYS_ERROR


class PasswordBanWordError(PasswordPolicyError):
    """Base exception class for password policy service errors."""

    code = ErrorCodes.PASSWORD_BAN_WORD_ERROR


class PasswordBanWordFileHasDuplicatesError(PasswordBanWordError):
    """Exception raised when a ban word already exists."""

    code = ErrorCodes.PASSWORD_BAN_WORD_FILE_HAS_DUPLICATES_ERROR


class PasswordBanWordTooLongError(PasswordBanWordError):
    """Exception raised when a ban word too long."""

    code = ErrorCodes.PASSWORD_BAN_WORD_TOO_LONG_ERROR


class PasswordBanWordWrongFileExtensionError(PasswordBanWordError):
    """Exception raised when a ban words file has wrong extension."""

    code = ErrorCodes.PASSWORD_BAN_WORD_WRONG_FILE_EXTENSION_ERROR
