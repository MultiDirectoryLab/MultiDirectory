"""Exceptions for DHCP manager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, unique

from errors import BaseDomainException


@unique
class ErrorCodes(IntEnum):
    """Error codes."""

    BASE_ERROR = 0
    DHCP_API_ERROR = 1
    DHCP_VALIDATION_ERROR = 2
    DHCP_CONNECTION_ERROR = 3
    DHCP_OPERATION_ERROR = 4
    DHCP_ENTRY_ADD_ERROR = 5
    DHCP_ENTRY_NOT_FOUND_ERROR = 6
    DHCP_ENTRY_DELETE_ERROR = 7
    DHCP_ENTRY_UPDATE_ERROR = 8
    DHCP_CONFLICT_ERROR = 9
    DHCP_UNSUPPORTED_ERROR = 10


class DHCPError(BaseDomainException):
    """DHCP base exception."""

    code: ErrorCodes = ErrorCodes.BASE_ERROR


class DHCPAPIError(DHCPError):
    """DHCP API error."""

    code = ErrorCodes.DHCP_API_ERROR


class DHCPValidatonError(DHCPError):
    """DHCP validation error."""

    code = ErrorCodes.DHCP_VALIDATION_ERROR


class DHCPConnectionError(ConnectionError):
    """DHCP connection error."""

    code = ErrorCodes.DHCP_CONNECTION_ERROR


class DHCPOperationError(DHCPError):
    """DHCP operation error."""

    code = ErrorCodes.DHCP_OPERATION_ERROR


class DHCPEntryAddError(DHCPError):
    """DHCP entry addition error."""

    code = ErrorCodes.DHCP_ENTRY_ADD_ERROR


class DHCPEntryNotFoundError(DHCPError):
    """DHCP entry not found error."""

    code = ErrorCodes.DHCP_ENTRY_NOT_FOUND_ERROR


class DHCPEntryDeleteError(DHCPError):
    """DHCP entry deletion error."""

    code = ErrorCodes.DHCP_ENTRY_DELETE_ERROR


class DHCPEntryUpdateError(DHCPError):
    """DHCP entry update error."""

    code = ErrorCodes.DHCP_ENTRY_UPDATE_ERROR


class DHCPConflictError(DHCPError):
    """DHCP conflict error."""

    code = ErrorCodes.DHCP_CONFLICT_ERROR


class DHCPUnsupportedError(DHCPError):
    """DHCP unsupported error."""

    code = ErrorCodes.DHCP_UNSUPPORTED_ERROR
