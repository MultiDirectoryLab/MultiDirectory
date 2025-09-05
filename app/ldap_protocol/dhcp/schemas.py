"""Schemas for DHCP manager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from .dataclasses import (
    DHCPLease,
    DHCPReservation,
    DHCPSharedNetwork,
    DHCPSubnet,
)
from .enums import KeaDHCPCommands

type _Args = (
    list[DHCPSubnet]
    | DHCPSubnet
    | DHCPLease
    | DHCPReservation
    | list[DHCPSharedNetwork]
    | None
)


@dataclass
class KeaDHCPBaseAPIRequest:
    """Base request for Kea DHCP API."""

    command: KeaDHCPCommands
    arguments: _Args = None
