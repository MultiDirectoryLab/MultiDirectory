"""Common business exceptions for role service class.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum

from errors import BaseDomainException


class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    ROLE_NOT_FOUND_ERROR = 1
    NO_VALID_GROUPS_ERROR = 2
    ACCESS_CONTROL_ENTRY_ADD_ERROR = 3
    ACCESS_CONTROL_ENTRY_NOT_FOUND_ERROR = 4
    ACCESS_CONTROL_ENTRY_UPDATE_ERROR = 5
    NO_VALID_DISTINGUISHED_NAME_ERROR = 6


class RoleError(BaseDomainException):
    """Base exception for all Role-related errors."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR


class RoleNotFoundError(RoleError):
    """Raised when a role is not found in the system."""

    code: ErrorCodes = ErrorCodes.ROLE_NOT_FOUND_ERROR


class NoValidGroupsError(RoleError):
    """Raised when no valid groups are provided for a role."""

    code: ErrorCodes = ErrorCodes.NO_VALID_GROUPS_ERROR


class AccessControlEntryAddError(RoleError):
    """Raised when there is an error with adding access control entries."""

    code: ErrorCodes = ErrorCodes.ACCESS_CONTROL_ENTRY_ADD_ERROR


class AccessControlEntryNotFoundError(RoleError):
    """Raised when an access control entry is not found."""

    code: ErrorCodes = ErrorCodes.ACCESS_CONTROL_ENTRY_NOT_FOUND_ERROR


class AccessControlEntryUpdateError(RoleError):
    """Raised when there is an error with updating access control entries."""

    code: ErrorCodes = ErrorCodes.ACCESS_CONTROL_ENTRY_UPDATE_ERROR


class NoValidDistinguishedNameError(RoleError):
    """Raised when there is an error with the distinguished name."""

    code: ErrorCodes = ErrorCodes.NO_VALID_DISTINGUISHED_NAME_ERROR
