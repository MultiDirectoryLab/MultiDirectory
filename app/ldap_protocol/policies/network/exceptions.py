"""Network policies exceptions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum

from errors import BaseDomainException, ErrorStatusCodes


class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    NETWORK_POLICY_ALREADY_EXISTS_ERROR = 1
    NETWORK_POLICY_NOT_FOUND_ERROR = 2
    LAST_ACTIVE_POLICY_ERROR = 3


class NetworkPolicyError(BaseDomainException):
    """Network policy error."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR
    status_code = ErrorStatusCodes.BAD_REQUEST


class NetworkPolicyAlreadyExistsError(NetworkPolicyError):
    """Network policy already exists error."""

    code = ErrorCodes.NETWORK_POLICY_ALREADY_EXISTS_ERROR


class NetworkPolicyNotFoundError(NetworkPolicyError):
    """Network policy not found error."""

    code = ErrorCodes.NETWORK_POLICY_NOT_FOUND_ERROR


class LastActivePolicyError(NetworkPolicyError):
    """Last active policy error."""

    code = ErrorCodes.LAST_ACTIVE_POLICY_ERROR
