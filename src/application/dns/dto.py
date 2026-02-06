"""DNS DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address


@dataclass
class DNSSettingDTO:
    """DNS settings entity."""

    zone_name: str | None
    dns_server_ip: str | IPv4Address | IPv6Address | None
    tsig_key: str | None
