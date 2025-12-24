"""Constants for DNS module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

DNS_FIRST_SETUP_RECORDS: list[dict[str, str]] = [
    {"name": "_ldap._tcp.", "value": "0 0 389 ", "type": "SRV"},
    {"name": "_ldaps._tcp.", "value": "0 0 636 ", "type": "SRV"},
    {"name": "_kerberos._tcp.", "value": "0 0 88 ", "type": "SRV"},
    {"name": "_kerberos._udp.", "value": "0 0 88 ", "type": "SRV"},
    {"name": "_kdc._tcp.", "value": "0 0 88 ", "type": "SRV"},
    {"name": "_kdc._udp.", "value": "0 0 88 ", "type": "SRV"},
    {"name": "_kpasswd._tcp.", "value": "0 0 464 ", "type": "SRV"},
    {"name": "_kpasswd._udp.", "value": "0 0 464 ", "type": "SRV"},
    # Record for PDC Emulator
    {
        "name": "_ldap._tcp.pdc._msdcs.",
        "value": "0 100 389 ",
        "type": "SRV",
    },
    # Records for DC Locator (for trusts)
    {
        "name": "_kerberos._tcp.dc._msdcs.",
        "value": "0 100 88 ",
        "type": "SRV",
    },
    {
        "name": "_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.",
        "value": "0 100 88 ",
        "type": "SRV",
    },
    {
        "name": "_ldap._tcp.dc._msdcs.",
        "value": "0 100 389 ",
        "type": "SRV",
    },
    {
        "name": "_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.",
        "value": "0 100 389 ",
        "type": "SRV",
    },
    # Records for Global Catalog
    {"name": "_gc._tcp.", "value": "0 100 3268 ", "type": "SRV"},
    {
        "name": "_ldap._tcp.Default-First-Site-Name._sites.gc._msdcs.",
        "value": "0 100 3268 ",
        "type": "SRV",
    },
    {
        "name": "_ldap._tcp.gc._msdcs.",
        "value": "0 100 3268 ",
        "type": "SRV",
    },
]
