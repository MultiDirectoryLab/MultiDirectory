"""Tests for error mapping.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum

import pytest

from ldap_protocol.dhcp.exceptions import ErrorCodes as DHCPErrorCodes
from ldap_protocol.dns.exceptions import ErrorCodes as DNSErrorCodes
from ldap_protocol.identity.exceptions.auth import ErrorCodes as AuthErrorCodes
from ldap_protocol.identity.exceptions.mfa import ErrorCodes as MFAErrorCodes
from ldap_protocol.kerberos.exceptions import ErrorCodes as KerberosErrorCodes
from ldap_protocol.ldap_schema.exceptions import (
    ErrorCodes as LDAPSchemaErrorCodes,
)
from ldap_protocol.policies.audit.exceptions import (
    ErrorCodes as AuditErrorCodes,
)
from ldap_protocol.policies.network.exceptions import (
    ErrorCodes as NetworkErrorCodes,
)
from ldap_protocol.policies.password.exceptions import (
    ErrorCodes as PasswordErrorCodes,
)
from ldap_protocol.session_storage.exceptions import (
    ErrorCodes as SessionStorageErrorCodes,
)


@pytest.mark.parametrize(
    ("error_enum"),
    [
        (AuditErrorCodes),
        (PasswordErrorCodes),
        (AuthErrorCodes),
        (MFAErrorCodes),
        (LDAPSchemaErrorCodes),
        (KerberosErrorCodes),
        (NetworkErrorCodes),
        (DHCPErrorCodes),
        (DNSErrorCodes),
        (SessionStorageErrorCodes),
    ],
)
@pytest.mark.asyncio
async def test_uniqueness_error_codes(
    error_enum: type[IntEnum],
) -> None:
    """Test uniqueness error codes."""
    error_codes = [i for i in error_enum.__members__.values()]
    assert len(set(error_codes)) == len(error_codes)

    for code in error_codes:
        assert code.value >= 0


@pytest.mark.parametrize(
    ("error_enum"),
    [
        (AuditErrorCodes),
        (PasswordErrorCodes),
        (AuthErrorCodes),
        (MFAErrorCodes),
        (LDAPSchemaErrorCodes),
        (KerberosErrorCodes),
        (NetworkErrorCodes),
        (DHCPErrorCodes),
        (DNSErrorCodes),
        (SessionStorageErrorCodes),
    ],
)
def test_error_codes_have_base_error(error_enum: type[IntEnum]) -> None:
    """Test that all error code enums have BASE_ERROR = 0."""
    assert hasattr(error_enum, "BASE_ERROR")
    assert error_enum.BASE_ERROR.value == 0


@pytest.mark.parametrize(
    ("error_enum"),
    [
        (AuditErrorCodes),
        (PasswordErrorCodes),
        (AuthErrorCodes),
        (MFAErrorCodes),
        (LDAPSchemaErrorCodes),
        (KerberosErrorCodes),
        (NetworkErrorCodes),
        (DHCPErrorCodes),
        (DNSErrorCodes),
        (SessionStorageErrorCodes),
    ],
)
def test_error_codes_are_sequential(error_enum: type[IntEnum]) -> None:
    """Test that error codes are sequential starting from 0."""
    codes = sorted([code.value for code in error_enum])
    assert codes == list(range(len(codes)))
