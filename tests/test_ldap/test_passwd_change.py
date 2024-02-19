"""Test password change."""

from asyncio import BaseEventLoop
from functools import partial

import pytest
from ldap3 import Connection
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.extra import TEST_DATA
from app.ldap_protocol.utils import get_user
from app.security import verify_password


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_anonymous_pwd_change(
    session: AsyncSession,
    event_loop: BaseEventLoop,
    ldap_client: Connection,
    settings: Settings,
) -> None:
    """Test anonymous pwd change."""
    settings.USE_CORE_TLS = True

    user_dn = "cn=user0,ou=users,dc=md,dc=test"
    password = TEST_DATA[1]['children'][0]['organizationalPerson']['password']
    new_test_password = 'password123'  # noqa
    await event_loop.run_in_executor(None, ldap_client.bind)

    result = await event_loop.run_in_executor(
        None,
        partial(  # noqa: S106
            ldap_client.extend.standard.modify_password,
            user_dn,
            old_password=password,
            new_password=new_test_password,
        ))

    assert result

    user = await get_user(session, user_dn)
    assert user

    assert verify_password(new_test_password, user.password)

    await event_loop.run_in_executor(None, ldap_client.unbind)

    settings.USE_CORE_TLS = False


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_bind_pwd_change(
    session: AsyncSession,
    event_loop: BaseEventLoop,
    ldap_client: Connection,
    settings: Settings,
) -> None:
    """Test anonymous pwd change."""
    settings.USE_CORE_TLS = True

    user_dn = "cn=user0,ou=users,dc=md,dc=test"
    password = TEST_DATA[1]['children'][0]['organizationalPerson']['password']
    new_test_password = 'password123'  # noqa
    await event_loop.run_in_executor(
        None, partial(ldap_client.rebind, user=user_dn, password=password))

    result = await event_loop.run_in_executor(
        None,
        partial(  # noqa: S106
            ldap_client.extend.standard.modify_password,
            old_password=password,
            new_password=new_test_password,
        ))

    assert result

    user = await get_user(session, user_dn)

    assert user is not None

    assert verify_password(new_test_password, user.password)

    await event_loop.run_in_executor(None, ldap_client.unbind)

    settings.USE_CORE_TLS = False
