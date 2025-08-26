"""Data classes for DHCP management.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network


@dataclass
class DHCPSubnet:
    """Data class for DHCP subnet."""

    id: int
    subnet: IPv4Network
    pools: list[IPv4Network]


@dataclass
class DHCPReservation:
    """Data class for DHCP reservation."""

    id: int
    ip_address: IPv4Address
    mac_address: str
    hostname: str | None


@dataclass
class DHCPLease:
    """Data class for DHCP lease."""

    id: int
    ip_address: IPv4Address
    mac_address: str
    hostname: str | None
    expires: datetime
