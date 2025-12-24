"""DNS DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

from .enums import DNSRecordType, PowerDNSRecordChangeType


@dataclass
class DNSSettingsDTO:
    """DNS settings entity."""

    domain: str
    dns_server_ip: IPv4Address | IPv6Address | None
    tsig_key: str | None


@dataclass
class DNSServerDTO:
    """DNS server entity."""

    id: str
    daemon_type: str
    version: str
    type: str = "server"


@dataclass
class DNSRecordDTO:
    """DNS record entity."""

    content: str
    disabled: bool
    modified_at: int | None = None


@dataclass
class DNSRRSetDTO:
    """DNS RRSet entity."""

    name: str
    type: DNSRecordType
    records: list[DNSRecordDTO]
    changetype: PowerDNSRecordChangeType | None = None
    ttl: int | None = None


@dataclass
class DNSZoneBaseDTO:
    """DNS zone entity."""

    id: str
    name: str
    rrsets: list[DNSRRSetDTO] = field(default_factory=list)
    type: str = "zone"


@dataclass
class DNSZoneMasterDTO(DNSZoneBaseDTO):
    """DNS master zone entity."""

    dnssec: bool = field(default=False)
    nameservers: list[str] = field(default_factory=list)
    kind: str = "Master"


@dataclass
class DNSZoneForwardDTO(DNSZoneBaseDTO):
    """DNS forward zone entity."""

    servers: list[str] = field(default_factory=list)
    recursion_desired: bool = field(default=False)
    kind: str = "Forwarded"
