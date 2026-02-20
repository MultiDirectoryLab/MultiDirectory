"""Constants for DNS module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_protocol.dns.enums import DNSRecordType

DNS_MANAGER_STATE_NAME = "DNSManagerState"
DNS_MANAGER_ZONE_NAME = "DNSManagerZoneName"
DNS_MANAGER_IP_ADDRESS_NAME = "DNSManagerIpAddress"
DNS_MANAGER_TSIG_KEY_NAME = "DNSManagerTSIGKey"

DNS_FIRST_SETUP_RECORDS: list[dict[str, str | DNSRecordType]] = [
    {"name": "_ldap._tcp.", "value": "0 0 389 ", "type": DNSRecordType.SRV},
    {"name": "_ldaps._tcp.", "value": "0 0 636 ", "type": DNSRecordType.SRV},
    {"name": "_kerberos._tcp.", "value": "0 0 88 ", "type": DNSRecordType.SRV},
    {"name": "_kerberos._udp.", "value": "0 0 88 ", "type": DNSRecordType.SRV},
    {"name": "_kdc._tcp.", "value": "0 0 88 ", "type": DNSRecordType.SRV},
    {"name": "_kdc._udp.", "value": "0 0 88 ", "type": DNSRecordType.SRV},
    {"name": "_kpasswd._tcp.", "value": "0 0 464 ", "type": DNSRecordType.SRV},
    {"name": "_kpasswd._udp.", "value": "0 0 464 ", "type": DNSRecordType.SRV},
    # Record for PDC Emulator
    {
        "name": "_ldap._tcp.pdc._msdcs.",
        "value": "0 100 389 ",
        "type": DNSRecordType.SRV,
    },
    # Records for DC Locator (for trusts)
    {
        "name": "_kerberos._tcp.dc._msdcs.",
        "value": "0 100 88 ",
        "type": DNSRecordType.SRV,
    },
    {
        "name": "_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.",
        "value": "0 100 88 ",
        "type": DNSRecordType.SRV,
    },
    {
        "name": "_ldap._tcp.dc._msdcs.",
        "value": "0 100 389 ",
        "type": DNSRecordType.SRV,
    },
    {
        "name": "_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.",
        "value": "0 100 389 ",
        "type": DNSRecordType.SRV,
    },
    # Records for Global Catalog
    {"name": "_gc._tcp.", "value": "0 100 3268 ", "type": DNSRecordType.SRV},
    {
        "name": "_ldap._tcp.Default-First-Site-Name._sites.gc._msdcs.",
        "value": "0 100 3268 ",
        "type": DNSRecordType.SRV,
    },
    {
        "name": "_ldap._tcp.gc._msdcs.",
        "value": "0 100 3268 ",
        "type": DNSRecordType.SRV,
    },
]
