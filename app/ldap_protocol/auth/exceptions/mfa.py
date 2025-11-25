"""Exception classes for multi-factor authentication (MFA) related errors.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum

from errors import BaseDomainException


class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    FORBIDDEN_ERROR = 1
    MFA_REQUIRED_ERROR = 2
    MFA_TOKEN_ERROR = 3
    MFA_API_ERROR = 4
    MFA_CONNECT_ERROR = 5
    MISSING_MFA_CREDENTIALS_ERROR = 6
    INVALID_CREDENTIALS_ERROR = 7
    NETWORK_POLICY_ERROR = 8
    NOT_FOUND_ERROR = 9
    AUTHENTICATION_ERROR = 10


class MFAError(BaseDomainException):
    """Base exception for MFA identity-related errors."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR


class ForbiddenError(MFAError):
    """Raised when an action is forbidden."""

    code = ErrorCodes.FORBIDDEN_ERROR


class MFARequiredError(MFAError):
    """Raised when MFA is required for authentication."""

    code = ErrorCodes.MFA_REQUIRED_ERROR


class MFATokenError(MFAError):
    """Raised when an MFA token is invalid or missing."""

    code = ErrorCodes.MFA_TOKEN_ERROR


class MFAAPIError(MFAError):
    """Raised when an MFA API error occurs."""

    code = ErrorCodes.MFA_API_ERROR


class MFAConnectError(MFAError):
    """Raised when an MFA connect error occurs."""

    code = ErrorCodes.MFA_CONNECT_ERROR


class MissingMFACredentialsError(MFAError):
    """Raised when MFA credentials are missing or not configured."""

    code = ErrorCodes.MISSING_MFA_CREDENTIALS_ERROR


class InvalidCredentialsError(MFAError):
    """Raised when provided credentials are invalid."""

    code = ErrorCodes.INVALID_CREDENTIALS_ERROR


class NetworkPolicyError(MFAError):
    """Raised when a network policy violation occurs."""

    code = ErrorCodes.NETWORK_POLICY_ERROR


class NotFoundError(MFAError):
    """Raised when a required resource is not found user, MFA config."""

    code = ErrorCodes.NOT_FOUND_ERROR


class AuthenticationError(MFAError):
    """Raised when an authentication attempt fails."""

    code = ErrorCodes.AUTHENTICATION_ERROR
