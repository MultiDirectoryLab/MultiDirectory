from functools import partial
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.extra import TEST_DATA
from app.ldap_protocol.dialogue import Session
from app.ldap_protocol.ldap_requests.bind import (
    BindRequest,
    BindResponse,
    LDAPCodes,
    SimpleAuthentication,
    UnbindRequest,
)
from app.models.ldap3 import Directory, User
from app.security import get_password_hash


@pytest.mark.asyncio()
async def test_bind_ok_and_unbind(
        session: AsyncSession, ldap_session: Session):
    """Test ok bind."""
    class MutePolicyBindRequest(BindRequest):
        @staticmethod
        async def is_user_group_valid(*args, **kwargs):
            return True

    directory = Directory(name='user0', object_class='')
    user = User(
        sam_accout_name='user0',
        user_principal_name='user0',
        mail='user0',
        display_name='user0',
        password=get_password_hash('password'),
        directory=directory,
    )
    session.add_all([directory, user])
    await session.commit()

    bind = MutePolicyBindRequest(
        version=0,
        name=user.sam_accout_name,
        AuthenticationChoice=SimpleAuthentication(password='password'),  # noqa
    )

    result = await anext(bind.handle(ldap_session, session))
    assert result == BindResponse(result_code=LDAPCodes.SUCCESS)
    assert ldap_session.user.sam_accout_name == user.sam_accout_name  # type: ignore  # noqa

    with pytest.raises(StopAsyncIteration):
        await anext(UnbindRequest().handle(ldap_session, session))
    assert ldap_session.user is None


@pytest.mark.asyncio()
async def test_bind_invalid_password_or_user(
        session: AsyncSession, ldap_session: Session):
    """Test invalid password bind."""
    directory = Directory(name='user0', object_class='')
    user = User(
        sam_accout_name='user0',
        user_principal_name='user0',
        mail='user0',
        display_name='user0',
        password=get_password_hash('password'),
        directory=directory,
    )
    session.add_all([directory, user])
    await session.commit()

    bind = BindRequest(
        version=0,
        name='user0',
        AuthenticationChoice=SimpleAuthentication(password='fail'),  # noqa
    )

    bad_response = BindResponse(
        result_code=LDAPCodes.INVALID_CREDENTIALS,
        matchedDN='',
        errorMessage=(
            '80090308: LdapErr: DSID-0C090447, '
            'comment: AcceptSecurityContext error, '
            'data 52e, v3839'),
    )

    result = await anext(bind.handle(ldap_session, session))
    assert result == bad_response
    assert ldap_session.user is None

    bind = BindRequest(
        version=0,
        name='user1',
        AuthenticationChoice=SimpleAuthentication(password='password'),  # noqa
    )

    result = await anext(bind.handle(ldap_session, session))
    assert result == bad_response
    assert ldap_session.user is None


@pytest.mark.asyncio()
async def test_anonymous_bind(session: AsyncSession, ldap_session: Session):
    """Test anonymous."""
    bind = BindRequest(
        version=0,
        name='',
        AuthenticationChoice=SimpleAuthentication(password=''),  # noqa
    )

    result = await anext(bind.handle(ldap_session, session))
    assert result == BindResponse(result_code=LDAPCodes.SUCCESS)
    assert ldap_session.user is None


@pytest.mark.asyncio()
async def test_anonymous_unbind(session: AsyncSession, ldap_session: Session):
    """Test anonymous call."""
    ldap_session.delete_user = AsyncMock()  # type: ignore
    with pytest.raises(StopAsyncIteration):
        await anext(UnbindRequest().handle(ldap_session, session))
    assert ldap_session.user is None
    ldap_session.delete_user.assert_called()


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_ldap3_bind(session, ldap_client, event_loop):
    """Test ldap3 bind."""
    user = TEST_DATA[1]['children'][0][
        'organizationalPerson']['sam_accout_name']
    password = TEST_DATA[1]['children'][0]['organizationalPerson']['password']

    assert not ldap_client.bound

    result = await event_loop.run_in_executor(None, ldap_client.bind)
    assert result
    assert ldap_client.bound

    result = await event_loop.run_in_executor(
        None, partial(ldap_client.rebind, user=user, password=password))
    assert result
    assert ldap_client.bound

    result = await event_loop.run_in_executor(None, ldap_client.unbind)
    assert not ldap_client.bound
