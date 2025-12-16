"""Test search with ldaputil.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio

import pytest

from config import Settings
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_global_session")
@pytest.mark.usefixtures("global_session")
async def test_ldap_search(
    global_settings: Settings,
    creds: TestCreds,
) -> None:
    """Test ldapsearch on server."""
    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-x",
        "-H",
        f"ldap://{global_settings.HOST}:{global_settings.GLOBAL_LDAP_PORT}",
        "-D",
        creds.un,
        "-w",
        creds.pw,
        "-b",
        "dc=md,dc=test",
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    print("SOSI")
    print(data)
    print(result)
    assert result == 0
    assert "dn: cn=groups,dc=md,dc=test" in data
    assert "dn: cn=users,dc=md,dc=test" in data
    assert "dn: cn=user0,cn=users,dc=md,dc=test" in data
