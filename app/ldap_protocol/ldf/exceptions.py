"""LDF processing exceptions."""

from enum import IntEnum

from errors import BaseDomainException


class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    LDF_VERSION_ALREADY_EXISTS = 1
    LDF_VERSION_NOT_FOUND = 2


class LdfError(BaseDomainException):
    """Base LDF error."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR


class LdfVersionAlreadyExistsError(LdfError):
    """LDF version already exists."""

    code = ErrorCodes.LDF_VERSION_ALREADY_EXISTS


class LdfVersionNotFoundError(LdfError):
    """LDF version not found."""

    code = ErrorCodes.LDF_VERSION_NOT_FOUND
