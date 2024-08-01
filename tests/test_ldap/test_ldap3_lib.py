"""Test ldap3 lib call.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from asyncio import BaseEventLoop
from functools import partial

import pytest
from ldap3 import Connection

from tests.conftest import TestCreds


@pytest.mark.asyncio
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


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap3_search_memberof(
        ldap_client: Connection,
        event_loop: BaseEventLoop,
        creds: TestCreds) -> None:
    """Test ldap3 search memberof."""
    member = 'cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test'
    await event_loop.run_in_executor(
        None, partial(ldap_client.rebind, user=creds.un, password=creds.pw))

    result = await event_loop.run_in_executor(
        None,
        partial(
            ldap_client.search, 'dc=md,dc=test',
            '(memberOf=cn=developers,cn=groups,dc=md,dc=test)',
        ))

    assert result
    assert ldap_client.entries
    assert ldap_client.entries[0].entry_dn == member
