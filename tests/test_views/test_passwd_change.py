"""Test password change."""

from functools import partial

import pytest

from app.extra import TEST_DATA, setup_enviroment
from app.ldap_protocol.utils import get_user
from app.security import verify_password


@pytest.mark.asyncio()
async def test_anonymous_pwd_change(
    session,
    event_loop,
    ldap_client,
    settings,
):
    """Test anonymous pwd change."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    settings.USE_CORE_TLS = True

    user = "cn=user0,ou=users,dc=md,dc=test"
    password = TEST_DATA[1]['children'][0]['organizationalPerson']['password']
    new_test_password = 'password123'  # noqa
    await event_loop.run_in_executor(None, ldap_client.bind)

    result = await event_loop.run_in_executor(
        None,
        partial(  # noqa: S106
            ldap_client.extend.standard.modify_password,
            user,
            old_password=password,
            new_password=new_test_password,
        ))

    assert result

    user = await get_user(session, user)

    assert verify_password(new_test_password, user.password)

    await event_loop.run_in_executor(None, ldap_client.unbind)

    settings.USE_CORE_TLS = False


@pytest.mark.asyncio()
async def test_bind_pwd_change(
    session,
    event_loop,
    ldap_client,
    settings,
):
    """Test anonymous pwd change."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    settings.USE_CORE_TLS = True

    user = "cn=user0,ou=users,dc=md,dc=test"
    password = TEST_DATA[1]['children'][0]['organizationalPerson']['password']
    new_test_password = 'password123'  # noqa
    await event_loop.run_in_executor(
        None, partial(ldap_client.rebind, user=user, password=password))

    result = await event_loop.run_in_executor(
        None,
        partial(  # noqa: S106
            ldap_client.extend.standard.modify_password,
            old_password=password,
            new_password=new_test_password,
        ))

    assert result

    user = await get_user(session, user)

    assert verify_password(new_test_password, user.password)

    await event_loop.run_in_executor(None, ldap_client.unbind)

    settings.USE_CORE_TLS = False
