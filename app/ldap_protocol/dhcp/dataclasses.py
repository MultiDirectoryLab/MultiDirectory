"""Data classes for DHCP management.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network


@dataclass
class DHCPPool:
    """Data class for DHCP pool."""

    pool: IPv4Network


@dataclass
class DHCPOptionData:
    """Data class for DHCP option data."""

    name: str
    data: IPv4Address | IPv4Network | str


@dataclass
class DHCPSubnet:
    """Data class for DHCP subnet."""

    id: int | None = None
    subnet: IPv4Network | None = None
    pools: list[DHCPPool] | None = None
    option_data: list[DHCPOptionData] | None = None


@dataclass
class DHCPSharedNetwork:
    """Data class for DHCP shared network."""

    name: str
    subnet4: list[DHCPSubnet]


@dataclass
class DHCPReservation:
    """Data class for DHCP reservation."""

    ip_address: IPv4Address
    subnet_id: int | None = None
    hw_address: str | None = None
    hostname: str | None = None
    identifier: str | None = None
    identifier_type: str | None = None
    operation_target: str | None = None


@dataclass
class DHCPLease:
    """Data class for DHCP lease."""

    id: int | None = None
    ip_address: IPv4Address | None = None
    mac_address: str | None = None
    hostname: str | None = None
    expires: datetime | None = None
