"""Constants for DNS module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_protocol.dns.enums import DNSRecordType

DNS_MANAGER_STATE_NAME = "DNSManagerState"
DNS_MANAGER_ZONE_NAME = "DNSManagerZoneName"
DNS_MANAGER_IP_ADDRESS_NAME = "DNSManagerIpAddress"
DNS_MANAGER_TSIG_KEY_NAME = "DNSManagerTSIGKey"

DEFAULT_FORWARD_ZONE_NAMES: list[str] = [
    ".",
    "b.e.f.ip6.arpa.",
    "a.e.f.ip6.arpa.",
    "23.172.in-addr.arpa.",
    "21.172.in-addr.arpa.",
    "254.169.in-addr.arpa.",
    "20.172.in-addr.arpa.",
    "17.172.in-addr.arpa.",
    "31.172.in-addr.arpa.",
    "22.172.in-addr.arpa.",
    "16.172.in-addr.arpa.",
    "19.172.in-addr.arpa.",
    "24.172.in-addr.arpa.",
    "168.192.in-addr.arpa.",
    "10.in-addr.arpa.",
    "8.e.f.ip6.arpa.",
    "127.in-addr.arpa.",
    "113.0.203.in-addr.arpa.",
    "26.172.in-addr.arpa.",
    "27.172.in-addr.arpa.",
    "8.b.d.0.1.0.0.2.ip6.arpa.",
    "28.172.in-addr.arpa.",
    "d.f.ip6.arpa.",
    "18.172.in-addr.arpa.",
    "30.172.in-addr.arpa.",
    "9.e.f.ip6.arpa.",
    "100.51.198.in-addr.arpa.",
    "255.255.255.255.in-addr.arpa.",
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
    "29.172.in-addr.arpa.",
    "0.in-addr.arpa.",
    "25.172.in-addr.arpa.",
    "2.0.192.in-addr.arpa.",
]

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
