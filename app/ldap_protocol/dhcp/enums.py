"""Enums.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, StrEnum


class DHCPManagerState(StrEnum):
    """DHCP manager states."""

    NOT_CONFIGURED = "0"
    KEA_DHCP = "1"


class KeaDHCPCommands(StrEnum):
    """Kea DHCP API commands."""

    SUBNET4_ADD = "subnet4-add"
    SUBNET4_DEL = "subnet4-del"
    SUBNET4_LIST = "subnet4-list"
    SUBNET4_GET = "subnet4-get"
    SUBNET4_UPDATE = "subnet4-update"
    LEASE4_ADD = "lease4-add"
    LEASE4_DEL = "lease4-del"
    LEASE4_LIST = "lease4-get-all"
    LEASE4_GET_BY_HW_ADDRESS = "lease4-get-by-hw-address"
    LEASE4_GET_BY_HOSTNAME = "lease4-get-by-hostname"
    RESERVATION_ADD = "reservation-add"
    RESERVATION_DEL = "reservation-del"
    RESERVATION_LIST = "reservation-get-all"


class KeaDHCPResultCodes(IntEnum):
    """Kea DHCP API result codes.

    0 - SUCCESS: Command completed successfully
    1 - ERROR: An error occurred
    2 - UNSUPPORTED: Command is not supported
    3 - EMPTY: Command was completed successfully,
    but no data was affected or returned
    4 - CONFLICT: Command could not apply requested configuration changes
    because they were in conflict with the server state
    """

    SUCCESS = 0
    ERROR = 1
    UNSUPPORTED = 2
    EMPTY = 3
    CONFLICT = 4
