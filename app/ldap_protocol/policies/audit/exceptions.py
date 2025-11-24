"""Audit exceptions module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum

from errors import BaseDomainException, ErrorStatusCodes


class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    AUDIT_NOT_FOUND_ERROR = 1
    AUDIT_ALREADY_EXISTS_ERROR = 2
    AUDIT_DESTINATION_NOT_FOUND_ERROR = 3
    AUDIT_DESTINATION_ALREADY_EXISTS_ERROR = 4

    AUDIT_DESTINATION_NOT_FOUND_ERROR2 = 6
    AUDIT_DESTINATION_ALREADY_EXISTS_ERROR2 = 5


class AuditError(BaseDomainException):
    """Audit error."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR
    status_code: ErrorStatusCodes = ErrorStatusCodes.BAD_REQUEST


class AuditNotFoundError(AuditError):
    """Exception raised when an audit model is not found."""

    code = ErrorCodes.AUDIT_NOT_FOUND_ERROR


class AuditAlreadyExistsError(AuditError):
    """Exception raised when an audit model already exists."""

    code = ErrorCodes.AUDIT_ALREADY_EXISTS_ERROR
