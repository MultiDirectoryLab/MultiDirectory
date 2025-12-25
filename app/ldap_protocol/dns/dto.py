"""DNS DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

from .enums import DNSRecordType, PowerDNSRecordChangeType, PowerDNSZoneType


@dataclass
class DNSSettingsDTO:
    """DNS settings DTO."""

    domain: str
    dns_server_ip: IPv4Address | IPv6Address | None
    tsig_key: str | None


@dataclass
class DNSServerDTO:
    """DNS server DTO."""

    id: str
    daemon_type: str
    version: str
    type: str = "server"


@dataclass
class DNSRecordDTO:
    """DNS record DTO."""

    content: str
    disabled: bool
    modified_at: int | None = None


@dataclass
class DNSRRSetDTO:
    """DNS RRSet(Resource Record Set) DTO."""

    name: str
    type: DNSRecordType
    records: list[DNSRecordDTO]
    changetype: PowerDNSRecordChangeType | None = None
    ttl: int | None = None


@dataclass
class DNSZoneBaseDTO:
    """DNS zone DTO."""

    id: str
    name: str
    rrsets: list[DNSRRSetDTO] = field(default_factory=list)
    type: str = "zone"


@dataclass
class DNSMasterZoneDTO(DNSZoneBaseDTO):
    """DNS master zone DTO."""

    dnssec: bool = field(default=False)
    nameservers: list[str] = field(default_factory=list)
    kind: PowerDNSZoneType = PowerDNSZoneType.MASTER


@dataclass
class DNSForwardZoneDTO(DNSZoneBaseDTO):
    """DNS forward zone DTO."""

    servers: list[str] = field(default_factory=list)
    recursion_desired: bool = field(default=False)
    kind: PowerDNSZoneType = PowerDNSZoneType.FORWARDED
