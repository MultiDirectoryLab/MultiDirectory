"""Test ldap3 lib call."""

from asyncio import BaseEventLoop
from functools import partial

import pytest
from ldap3 import Connection

from tests.conftest import TestCreds


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap3_search(
        ldap_client: Connection,
        event_loop: BaseEventLoop,
        creds: TestCreds) -> None:
    """Test ldap3 search."""
    await event_loop.run_in_executor(
        None, partial(ldap_client.rebind, user=creds.un, password=creds.pw))

    result = await event_loop.run_in_executor(
        None,
        partial(
            ldap_client.search, 'dc=md,dc=test', '(objectclass=*)',
        ))

    assert result
    assert ldap_client.entries
