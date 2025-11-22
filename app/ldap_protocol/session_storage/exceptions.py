"""Exceptions for session storage.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum

from errors import BaseDomainException, ErrorStatusCodes


class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    INVALID_KEY_ERROR = 1
    MISSING_DATA_ERROR = 2
    INVALID_IP_ERROR = 3
    INVALID_USER_AGENT_ERROR = 4
    INVALID_SIGNATURE_ERROR = 5
    INVALID_DATA_ERROR = 6
    USER_NOT_FOUND_ERROR = 7


class SessionStorageError(BaseDomainException):
    """Session storage error."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR
    status_code: ErrorStatusCodes = ErrorStatusCodes.BAD_REQUEST


class SessionStorageInvalidKeyError(SessionStorageError):
    """Session storage invalid key error."""

    code = ErrorCodes.INVALID_KEY_ERROR


class SessionStorageMissingDataError(SessionStorageError):
    """Session storage missing data error."""

    code = ErrorCodes.MISSING_DATA_ERROR


class SessionStorageInvalidIpError(SessionStorageError):
    """Session storage invalid ip error."""

    code = ErrorCodes.INVALID_IP_ERROR


class SessionStorageInvalidUserAgentError(SessionStorageError):
    """Session storage invalid user agent error."""

    code = ErrorCodes.INVALID_USER_AGENT_ERROR


class SessionStorageInvalidSignatureError(SessionStorageError):
    """Session storage invalid signature error."""

    code = ErrorCodes.INVALID_SIGNATURE_ERROR


class SessionStorageInvalidDataError(SessionStorageError):
    """Session storage invalid data error."""

    code = ErrorCodes.INVALID_DATA_ERROR


class SessionUserNotFoundError(SessionStorageError):
    """Session storage user not found error."""

    code = ErrorCodes.USER_NOT_FOUND_ERROR
