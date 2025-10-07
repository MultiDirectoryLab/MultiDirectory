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

    id: int | None = None
    subnet: IPv4Network | None = None
    pools: list[DHCPPool] | None = None
    valid_lifetime: int | None = None
    option_data: list[DHCPOptionData] | None = None


@dataclass
class DHCPReservation:
    """Data class for DHCP reservation."""

    ip_address: IPv4Address | None = None
    subnet_id: int | None = None
    mac_address: str | None = None
    hostname: str | None = None
    identifier: str | None = None
    identifier_type: str = "hw-address"
    operation_target: str = "all"


@dataclass
class DHCPLease:
    """Data class for DHCP lease."""

    id: int | None = None
    subnet_id: int | None = None
    ip_address: IPv4Address | None = None
    mac_address: str | None = None
    hostname: str | None = None
    cltt: int | None = None
    lifetime: int | None = None
    expires: datetime | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        """Calculate the expiration time of the lease."""
        if self.cltt and self.lifetime:
            self.expires = datetime.fromtimestamp(self.cltt + self.lifetime)
