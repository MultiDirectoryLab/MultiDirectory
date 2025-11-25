"""Exceptions for LDAP requests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum

from errors import BaseDomainException


class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    MODIFY_ERROR = 1
    PASSWORD_MODIFY_ERROR = 2
    PASSWORD_MODIFY_USER_NOT_FOUND_ERROR = 3
    PASSWORD_MODIFY_USER_NOT_ALLOWED_ERROR = 4
    PASSWORD_MODIFY_PASSWORD_CHANGE_RESTRICTED_ERROR = 5
    PASSWORD_MODIFY_NO_PASSWORD_MODIFY_ACCESS_ERROR = 6
    PASSWORD_MODIFY_KADMIN_ERROR = 7
    PASSWORD_MODIFY_NO_USER_PROVIDED_ERROR = 8


class ModifyError(BaseDomainException):
    """Modify error."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR


class PasswordModifyError(ModifyError):
    """Password modify error."""

    code: ErrorCodes = ErrorCodes.PASSWORD_MODIFY_ERROR


class PasswordModifyUserNotFoundError(PasswordModifyError):
    """Password modify user not found error."""

    code: ErrorCodes = ErrorCodes.PASSWORD_MODIFY_USER_NOT_FOUND_ERROR


class PasswordModifyUserNotAllowedError(PasswordModifyError):
    """Password modify user not allowed error."""

    code: ErrorCodes = ErrorCodes.PASSWORD_MODIFY_USER_NOT_ALLOWED_ERROR


class PasswordModifyPasswordChangeRestrictedError(PasswordModifyError):
    """Password modify password change restricted error."""

    code: ErrorCodes = (
        ErrorCodes.PASSWORD_MODIFY_PASSWORD_CHANGE_RESTRICTED_ERROR
    )


class PasswordModifyNoPasswordModifyAccessError(PasswordModifyError):
    """Password modify no password modify access error."""

    code: ErrorCodes = (
        ErrorCodes.PASSWORD_MODIFY_NO_PASSWORD_MODIFY_ACCESS_ERROR
    )


class PasswordModifyKadminError(PasswordModifyError):
    """Password modify kadmin error."""

    code: ErrorCodes = ErrorCodes.PASSWORD_MODIFY_KADMIN_ERROR


class PasswordModifyNoUserProvidedError(PasswordModifyError):
    """Password modify no user provided error."""

    code: ErrorCodes = ErrorCodes.PASSWORD_MODIFY_NO_USER_PROVIDED_ERROR
