"""Test ldap3 lib call."""

from asyncio import BaseEventLoop
from functools import partial

import pytest
from ldap3 import Connection

from app.extra import TEST_DATA


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap3_search(
        ldap_client: Connection, event_loop: BaseEventLoop) -> None:
    """Test ldap3 search."""
    user = TEST_DATA[1]['children'][0][
        'organizationalPerson']['sam_accout_name']
    password = TEST_DATA[1]['children'][0]['organizationalPerson']['password']

    await event_loop.run_in_executor(
        None, partial(ldap_client.rebind, user=user, password=password))

    result = await event_loop.run_in_executor(
        None,
        partial(
            ldap_client.search, 'dc=md,dc=test', '(objectclass=*)',
        ))

    assert result
    assert ldap_client.entries
