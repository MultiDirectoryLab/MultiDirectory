"""Data classes for DHCP management.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass, field
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

    id: int | None = field(default=None)
    subnet: IPv4Network | None = field(default=None)
    pools: list[DHCPPool] | None = field(default=None)
    option_data: list[DHCPOptionData] | None = field(
        default=None,
    )


@dataclass
class DHCPSharedNetwork:
    """Data class for DHCP shared network."""

    name: str
    subnet4: list[DHCPSubnet]


@dataclass
class DHCPReservation:
    """Data class for DHCP reservation."""

    ip_address: IPv4Address
    subnet_id: int | None = field(default=None)
    hw_address: str | None = field(default=None)
    hostname: str | None = field(default=None)
    identifier: str | None = field(default=None)
    identifier_type: str | None = field(
        default=None,
    )
    operation_target: str | None = field(
        default=None,
    )


@dataclass
class DHCPLease:
    """Data class for DHCP lease."""

    id: int | None = field(default=None)
    ip_address: IPv4Address | None = field(default=None)
    mac_address: str | None = field(default=None)
    hostname: str | None = field(default=None)
    expires: datetime | None = field(default=None)
