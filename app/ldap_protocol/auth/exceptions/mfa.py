"""Exception classes for multi-factor authentication (MFA) related errors.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum

from errors import BaseDomainException, ErrorStatusCodes


class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    FORBIDDEN_ERROR = 1
    MFARequiredError = 2
    MFATokenError = 3
    MFAAPIError = 4
    MFAConnectError = 5
    MissingMFACredentialsError = 6
    InvalidCredentialsError = 7
    NetworkPolicyError = 8
    NotFoundError = 9
    AuthenticationError = 10


class MFAError(BaseDomainException):
    """Base exception for MFA identity-related errors."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR
    status_code: ErrorStatusCodes = ErrorStatusCodes.BAD_REQUEST


class ForbiddenError(MFAError):
    """Raised when an action is forbidden."""

    code = ErrorCodes.FORBIDDEN_ERROR


class MFARequiredError(MFAError):
    """Raised when MFA is required for authentication."""

    code = ErrorCodes.MFARequiredError


class MFATokenError(MFAError):
    """Raised when an MFA token is invalid or missing."""

    code = ErrorCodes.MFATokenError


class MFAAPIError(MFAError):
    """Raised when an MFA API error occurs."""

    code = ErrorCodes.MFAAPIError


class MFAConnectError(MFAError):
    """Raised when an MFA connect error occurs."""

    code = ErrorCodes.MFAConnectError


class MissingMFACredentialsError(MFAError):
    """Raised when MFA credentials are missing or not configured."""

    code = ErrorCodes.MissingMFACredentialsError


class InvalidCredentialsError(MFAError):
    """Raised when provided credentials are invalid."""

    code = ErrorCodes.InvalidCredentialsError


class NetworkPolicyError(MFAError):
    """Raised when a network policy violation occurs."""

    code = ErrorCodes.NetworkPolicyError


class NotFoundError(MFAError):
    """Raised when a required resource is not found user, MFA config."""

    code = ErrorCodes.NotFoundError


class AuthenticationError(MFAError):
    """Raised when an authentication attempt fails."""

    code = ErrorCodes.AuthenticationError
