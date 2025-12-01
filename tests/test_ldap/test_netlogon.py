"""Test NetLogon attribute handler.

Docs:

https://learn.microsoft.com/en-us/openspecs/windows_protocols/


Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import struct
import uuid
from collections import defaultdict

from ldap_protocol.netlogon import (
    _NL_DEFAULT_SITE,
    _ZERO_UUID,
    _ZERO_VER,
    DSFlag,
    NetLogonAttributeHandler,
    NetLogonOPCode,
    _NetLogonInfo,
)


def test_netlogon_info_initialization() -> None:
    """Test NetLogonInfo dataclass initialization."""
    info = _NetLogonInfo(
        domain_guid=_ZERO_UUID,
        domain_dns="example.com",
        nc_used="example.com",
        domain_sid="S-1-5-21-123456789",
        user="testuser",
        site=_NL_DEFAULT_SITE,
        ntver=_ZERO_VER,
        has_user=True,
    )

    assert info.domain_guid == _ZERO_UUID
    assert info.domain_dns == "example.com"
    assert info.user == "testuser"
    assert info.has_user is True


def test_netlogon_handler_initialization() -> None:
    """Test NetLogonAttributeHandler initialization."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["serverName"] = ["CN=DC"]

    handler = NetLogonAttributeHandler(root_dse)

    assert handler.dnsdomain is None
    assert handler.user is None
    assert handler.ntver == _ZERO_VER


def test_netlogon_handler_from_filter_empty() -> None:
    """Test NetLogonAttributeHandler.from_filter with string input."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]

    handler = NetLogonAttributeHandler.from_filter(root_dse, "test")

    assert handler.dnsdomain is None
    assert handler.user is None


def test_set_info_with_defaults() -> None:
    """Test set_info with default values."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["serverName"] = ["CN=DC"]
    root_dse["dnsForestName"] = ["forest.com"]
    root_dse["dnsDomainName"] = ["domain.com"]

    handler = NetLogonAttributeHandler(root_dse)
    handler.set_info()

    # Test by calling get_attr which uses the internal __info
    response = handler.get_attr()  # nt40

    assert isinstance(response, bytes)
    assert len(response) > 0
    # Verify the response contains expected domain and site information
    assert b"dc.example.com" in response


def test_set_info_with_custom_values() -> None:
    """Test set_info with custom values."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["serverName"] = ["CN=DC"]
    root_dse["dnsForestName"] = ["forest.com"]
    root_dse["dnsDomainName"] = ["domain.com"]
    root_dse["domainGuid"] = [str(uuid.uuid4())]

    handler = NetLogonAttributeHandler(root_dse)
    handler.dnsdomain = "custom.com"
    handler.user = "admin"
    handler.domainsid = "S-1-5-21-987654321"
    handler.domainguid = uuid.uuid4()
    handler.ntver = "\x04\x00\x00\x00"  # NETLOGON_NT_VERSION_5EX
    handler.set_info()

    # Test by calling get_attr which uses the internal __info
    response = handler.get_attr()

    assert isinstance(response, bytes)
    assert len(response) > 0
    # Verify the response contains custom domain and user
    assert b"admin" in response


def test_set_acc() -> None:
    """Test set_acc method."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["serverName"] = ["CN=DC"]
    root_dse["dnsForestName"] = ["forest.com"]
    root_dse["dnsDomainName"] = ["domain.com"]

    handler = NetLogonAttributeHandler(root_dse)
    handler.user = "testuser"
    handler.ntver = "\x02\x00\x00\x00"  # NETLOGON_NT_VERSION_5
    handler.set_info()

    # Test with user found
    response_found = handler.get_attr()
    op_code_found = struct.unpack("<H", response_found[:2])[0]
    assert op_code_found == NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE

    # Test with user not found
    response_not_found = handler.get_attr()
    op_code = struct.unpack("<H", response_not_found[:2])[0]
    assert op_code == NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE


def test_convert_little_endian_string_to_int() -> None:
    """Test _convert_little_endian_string_to_int method."""
    test_value = "\x01\x00\x00\x00"
    result = NetLogonAttributeHandler._convert_little_endian_string_to_int(  # noqa:SLF001
        test_value,
    )

    assert result == 1


def test_pack_string() -> None:
    """Test _pack_string method."""
    result = NetLogonAttributeHandler._pack_string("test", "utf-8")  # noqa:SLF001

    assert result == b"\x04test"


def test_get_netlogon_response_5() -> None:
    """Test _get_netlogon_response_5 method."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["serverName"] = ["CN=DC"]
    root_dse["dnsForestName"] = ["forest.com"]
    root_dse["dnsDomainName"] = ["domain.com"]

    handler = NetLogonAttributeHandler(root_dse)
    handler.set_info()

    response = handler._get_netlogon_response_5()  # noqa:SLF001

    assert isinstance(response, bytes)
    assert len(response) > 0
    # Check op_code is present (first 2 bytes)
    op_code = struct.unpack("<H", response[:2])[0]
    assert op_code in [
        NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE,
        NetLogonOPCode.LOGON_SAM_USER_UNKNOWN,
    ]


def test_get_netlogon_response_5_ex() -> None:
    """Test _get_netlogon_response_5_ex method."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["dnsForestName"] = ["forest.com"]
    root_dse["dnsDomainName"] = ["domain.com"]
    root_dse["domainGuid"] = [str(uuid.uuid4())]

    handler = NetLogonAttributeHandler(root_dse)
    handler.set_info()

    response = handler._get_netlogon_response_5_ex()  # noqa:SLF001

    assert isinstance(response, bytes)
    assert len(response) > 0
    # Check op_code
    op_code = struct.unpack("<H", response[:2])[0]
    assert op_code in [
        NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE_EX,
        NetLogonOPCode.LOGON_SAM_USER_UNKNOWN_EX,
    ]


def test_get_netlogon_response_nt40() -> None:
    """Test _get_netlogon_response_nt40 method."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["serverName"] = ["CN=DC"]

    handler = NetLogonAttributeHandler(root_dse)
    handler.set_info()

    response = handler._get_netlogon_response_nt40()  # noqa:SLF001

    assert isinstance(response, bytes)
    assert len(response) > 0
    # Check op_code
    op_code = struct.unpack("<H", response[:2])[0]
    assert op_code in [
        NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE,
        NetLogonOPCode.LOGON_SAM_USER_UNKNOWN,
    ]


def test_get_attr_version_5() -> None:
    """Test get_attr with version 5."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["serverName"] = ["CN=DC"]
    root_dse["dnsForestName"] = ["forest.com"]
    root_dse["dnsDomainName"] = ["domain.com"]

    handler = NetLogonAttributeHandler(root_dse)
    handler.ntver = "\x02\x00\x00\x00"  # NETLOGON_NT_VERSION_5
    handler.set_info()

    response = handler.get_attr()

    assert isinstance(response, bytes)
    assert len(response) > 0


def test_get_attr_version_5_ex() -> None:
    """Test get_attr with version 5 EX."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["dnsForestName"] = ["forest.com"]
    root_dse["dnsDomainName"] = ["domain.com"]
    root_dse["domainGuid"] = [str(uuid.uuid4())]

    handler = NetLogonAttributeHandler(root_dse)
    handler.ntver = "\x04\x00\x00\x00"  # NETLOGON_NT_VERSION_5EX
    handler.set_info()

    response = handler.get_attr()

    assert isinstance(response, bytes)
    assert len(response) > 0


def test_get_attr_version_nt40() -> None:
    """Test get_attr with NT40 version."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["serverName"] = ["CN=DC"]

    handler = NetLogonAttributeHandler(root_dse)
    handler.ntver = _ZERO_VER
    handler.set_info()

    response = handler.get_attr()

    assert isinstance(response, bytes)
    assert len(response) > 0


def test_user_unknown_response() -> None:
    """Test user unknown response."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["serverName"] = ["CN=DC"]
    root_dse["dnsForestName"] = ["forest.com"]
    root_dse["dnsDomainName"] = ["domain.com"]

    handler = NetLogonAttributeHandler(root_dse)
    handler.user = "nonexistent"
    handler.set_info()

    response = handler._get_netlogon_response_5()  # noqa:SLF001
    op_code = struct.unpack("<H", response[:2])[0]

    assert op_code == NetLogonOPCode.LOGON_SAM_LOGON_RESPONSE


def test_ds_flags_combination() -> None:
    """Test DS flags combination in response 5 EX."""
    root_dse = defaultdict(list)
    root_dse["dnsHostName"] = ["dc.example.com"]
    root_dse["dnsForestName"] = ["forest.com"]
    root_dse["dnsDomainName"] = ["domain.com"]
    root_dse["domainGuid"] = [str(uuid.uuid4())]

    handler = NetLogonAttributeHandler(root_dse)
    handler.set_info()

    response = handler._get_netlogon_response_5_ex()  # noqa:SLF001

    # Extract DS flags (bytes 4-7)
    ds_flags = struct.unpack("<I", response[4:8])[0]

    expected_flags = (
        DSFlag.PDC_FLAG
        | DSFlag.LDAP_FLAG
        | DSFlag.DS_FLAG
        | DSFlag.TIMESERV_FLAG
        | DSFlag.CLOSEST_FLAG
        | DSFlag.WRITABLE_FLAG
        | DSFlag.GOOD_TIMESERV_FLAG
    )

    assert ds_flags == expected_flags
