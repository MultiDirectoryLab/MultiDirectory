"""Schemas for DNS router.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel

from ldap_protocol.dns import DNSManagerState, DNSRecordType


class DNSServiceSetStateRequest(BaseModel):
    """DNS set state request schema."""

    state: DNSManagerState


class DNSServiceSetupRequest(BaseModel):
    """DNS setup request schema."""

    domain: str
    dns_ip_address: IPv4Address | IPv6Address | None = None
    tsig_key: str | None = None


class DNSServiceRecordBaseRequest(BaseModel):
    """DNS setup base schema."""

    record_name: str
    record_type: DNSRecordType


class DNSServiceRecordCreateRequest(DNSServiceRecordBaseRequest):
    """DNS create request schema."""

    record_value: str
    ttl: int | None = None


class DNSServiceRecordDeleteRequest(DNSServiceRecordBaseRequest):
    """DNS delete request schema."""

    record_value: str


class DNSServiceRecordUpdateRequest(DNSServiceRecordBaseRequest):
    """DNS update request schema."""

    record_value: str
    ttl: int | None = None


class DNSServiceForwardZoneRequest(BaseModel):
    """DNS zone create request scheme."""

    zone_name: str
    servers: list[str]


class DNSServiceMasterZoneRequest(BaseModel):
    """DNS zone create request scheme."""

    zone_name: str
    nameserver_ip: str
    dnssec: bool = False


class DNSServiceZoneDeleteRequest(BaseModel):
    """DNS zone delete request scheme."""

    zone_ids: list[str]


class DNSServiceForwardZoneCheckRequest(BaseModel):
    """Forwarder DNS server check request scheme."""

    dns_server_ips: list[IPv4Address | IPv6Address]
