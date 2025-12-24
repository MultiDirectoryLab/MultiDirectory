"""Enums for DNS module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import StrEnum


class DNSRecordType(StrEnum):
    """PowerDNS Record Types."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    SOA = "SOA"
    SRV = "SRV"
    PTR = "PTR"


class PowerDNSZoneType(StrEnum):
    """PowerDNS Zone Types."""

    MASTER = "Master"
    FORWARDED = "Forwarded"


class PowerDNSRecordChangeType(StrEnum):
    """PowerDNS Record Change Types."""

    REPLACE = "REPLACE"
    DELETE = "DELETE"
    EXTEND = "EXTEND"
    PRUNE = "PRUNE"


class DNSForwarderServerStatus(StrEnum):
    """Forwarder DNS server statuses."""

    VALIDATED = "validated"
    NOT_VALIDATED = "not validated"
    NOT_FOUND = "not found"


class DNSManagerState(StrEnum):
    """DNSManager state enum."""

    NOT_CONFIGURED = "0"
    SELFHOSTED = "1"
    HOSTED = "2"
