"""Test whoami.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from functools import partial

import pytest
from ldap3 import Connection

from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_anonymous_whoami(
    event_loop: asyncio.BaseEventLoop,
    ldap_client: Connection,
) -> None:
    """Test anonymous pwd change."""
    await event_loop.run_in_executor(None, partial(ldap_client.rebind))

    result = await event_loop.run_in_executor(
        None,
        ldap_client.extend.standard.who_am_i,
    )

    assert result is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_bind_whoami(
    event_loop: asyncio.BaseEventLoop,
    ldap_client: Connection,
    creds: TestCreds,
) -> None:
    """Test anonymous pwd change."""
    await event_loop.run_in_executor(
        None,
        partial(ldap_client.rebind, user=creds.un, password=creds.pw),
    )

    result = await event_loop.run_in_executor(
        None,
        ldap_client.extend.standard.who_am_i,
    )

    assert result == "u:user0"
