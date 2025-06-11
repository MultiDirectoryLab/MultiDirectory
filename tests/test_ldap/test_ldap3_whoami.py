"""Test whoami.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from aioldap3 import LDAPConnection


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_anonymous_whoami(
    anonymous_ldap_client: LDAPConnection,
) -> None:
    """Test anonymous pwd change."""
    result = await anonymous_ldap_client.whoami()

    assert result is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_bind_whoami(
    ldap_client: LDAPConnection,
) -> None:
    """Test anonymous pwd change."""
    result = await ldap_client.whoami()

    assert result == "u:user0"
