"""Exception classes for authentication-related errors.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum

from errors import BaseDomainException, ErrorStatusCodes


class ErrorCodes(IntEnum):
    """Identity error codes."""

    BASE_ERROR = 0
    UNAUTHORIZED_ERROR = 1
    ALREADY_CONFIGURED_ERROR = 2
    FORBIDDEN_ERROR = 3
    LOGIN_FAILED_ERROR = 4
    PASSWORD_POLICY_ERROR = 5
    USER_NOT_FOUND_ERROR = 6
    AUTH_VALIDATION_ERROR = 7


class AuthError(BaseDomainException):
    """Base exception for authentication identity-related errors."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR
    status_code: ErrorStatusCodes = ErrorStatusCodes.BAD_REQUEST


class UnauthorizedError(AuthError):
    """Raised when authentication fails due to invalid credentials."""

    code = ErrorCodes.UNAUTHORIZED_ERROR


class AlreadyConfiguredError(AuthError):
    """Raised when setup is attempted but already performed."""

    code = ErrorCodes.ALREADY_CONFIGURED_ERROR


class ForbiddenError(AuthError):
    """Raised when access is forbidden due to policy or group membership."""

    code = ErrorCodes.FORBIDDEN_ERROR


class LoginFailedError(AuthError):
    """Raised when login fails for reasons other than invalid credentials."""

    code = ErrorCodes.LOGIN_FAILED_ERROR


class PasswordPolicyError(AuthError):
    """Raised when a password does not meet policy requirements."""

    code = ErrorCodes.PASSWORD_POLICY_ERROR


class UserNotFoundError(AuthError):
    """Raised when a user is not found in the system."""

    code = ErrorCodes.USER_NOT_FOUND_ERROR


class AuthValidationError(AuthError):
    """Raised when there is a validation error during authentication."""

    code = ErrorCodes.AUTH_VALIDATION_ERROR
