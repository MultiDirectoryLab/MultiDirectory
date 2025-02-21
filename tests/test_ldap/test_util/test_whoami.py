"""Test whoami with ldaputil.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio

import pytest

from config import Settings
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_anonymous_whoami(settings: Settings) -> None:
    """Test anonymous whoami."""
    proc = await asyncio.create_subprocess_exec(
        "ldapwhoami",
        "-x",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
    )

    assert await proc.wait() == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_binded_whoami(settings: Settings, creds: TestCreds) -> None:
    """Test anonymous whoami."""
    proc = await asyncio.create_subprocess_exec(
        "ldapwhoami",
        "-x",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        creds.un,
        "-w",
        creds.pw,
    )

    assert await proc.wait() == 0
