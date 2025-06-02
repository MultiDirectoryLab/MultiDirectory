"""Test whoami.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest

from aioldap3 import LDAPConnection
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_anonymous_whoami(
    ldap_client: LDAPConnection,
    creds: TestCreds,
) -> None:
    """Test anonymous pwd change."""
    await ldap_client.bind(creds.un, creds.pw)

    result = await ldap_client.whoami()

    assert result == "u:user0"
