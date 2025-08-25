"""Enums.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import StrEnum


class DHCPManagerState(StrEnum):
    """DHCP manager states."""

    NOT_CONFIGURED = "0"
    KEA_DHCP = "1"


class KeaDHCPCommands(StrEnum):
    """Kea DHCP API commands."""

    NETWORK4_ADD = "network4-add"
    NETWORK4_DEL = "network4-del"
    NETWORK4_LIST = "network4-list"
    NETWORK4_GET = "network4-get"
    LEASE4_ADD = "lease4-add"
    LEASE4_DEL = "lease4-del"
    LEASE4_LIST = "lease4-list"
    LEASE4_GET_BY_HW_ADDRESS = "lease4-get-by-hw-address"
    LEASE4_GET_BY_HOSTNAME = "lease4-get-by-hostname"
    RESERVATION_ADD = "reservation-add"
    RESERVATION_DEL = "reservation-del"
    RESERVATION_LIST = "reservation-list"
