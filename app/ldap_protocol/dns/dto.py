"""DNS DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

from ldap_protocol.dns.enums import (
    DNSForwarderServerStatus,
    DNSRecordType,
    PowerDNSRecordChangeType,
    PowerDNSZoneType,
)


@dataclass
class CommandResponse:
    success: bool = True
    message: str = " "


@dataclass
class RuleEntry:
    id: int
    match: str
    action: str


@dataclass
class DNSdistRulesTable:
    rules: list[RuleEntry]
    count: int


@dataclass
class DNSdistCommand:
    command: str


@dataclass
class DNSdistCommandsDelta:
    delta: list[DNSdistCommand]
    count: int


@dataclass
class PowerDNSSettingsDTO:
    """PowerDNS related settings."""

    auth_server_ip: str
    recursor_server_ip: str


@dataclass
class DNSSettingsDTO:
    """DNS settings DTO."""

    domain: str
    dns_server_ip: IPv4Address | IPv6Address | None
    tsig_key: str | None
    default_nameserver: str
    power_dns_settings: PowerDNSSettingsDTO | None = field(default=None)


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


@dataclass
class DNSForwardServerStatus:
    """Forward DNS server status."""

    ip: str
    status: DNSForwarderServerStatus
    FQDN: str | None
