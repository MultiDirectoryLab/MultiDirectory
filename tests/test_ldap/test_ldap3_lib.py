"""Test ldap3 lib call.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from aioldap3 import LDAPConnection


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_ldap3_search(ldap_client: LDAPConnection) -> None:
    """Test ldap3 search."""
    result = await ldap_client.search(
        "dc=md,dc=test",
        "(objectclass=*)",
    )

    assert result
    assert result.entries


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_ldap3_search_memberof(ldap_client: LDAPConnection) -> None:
    """Test ldap3 search memberof."""
    member = "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test"

    result = await ldap_client.search(
        "dc=md,dc=test",
        "(memberOf=cn=developers,cn=groups,dc=md,dc=test)",
    )

    assert result
    assert result.entries
    assert result.entries[0]["dn"] == member
