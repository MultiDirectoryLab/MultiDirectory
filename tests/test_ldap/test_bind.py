"""Test bind ldap3 + white case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from asyncio import BaseEventLoop
from functools import partial
from unittest.mock import AsyncMock, Mock

import pytest
from dishka import AsyncContainer, Scope
from ldap3 import PLAIN, SASL, Connection
from sqlalchemy.ext.asyncio import AsyncSession

from app.ldap_protocol.dialogue import LDAPSession
from config import Settings
from ldap_protocol.dependency import resolve_deps
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.ldap_requests.bind import (
    BindRequest,
    BindResponse,
    LDAPCodes,
    SimpleAuthentication,
    UnbindRequest,
)
from models.ldap3 import Directory, User
from security import get_password_hash
from tests.conftest import MutePolicyBindRequest, TestCreds


@pytest.mark.asyncio()
@pytest.mark.usefixtures('session')
async def test_bind_ok_and_unbind(
    session: AsyncSession,
    ldap_session: LDAPSession,
    settings: Settings,
    kadmin: AbstractKadmin,
) -> None:
    """Test ok bind."""
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

    result = await anext(bind.handle(
        session, ldap_session, kadmin, settings, None))
    assert result == BindResponse(result_code=LDAPCodes.SUCCESS)
    assert ldap_session.user.sam_accout_name == user.sam_accout_name  # type: ignore  # noqa

    with pytest.raises(StopAsyncIteration):
        await anext(UnbindRequest().handle(ldap_session))
    assert ldap_session.user is None


@pytest.mark.asyncio()
@pytest.mark.usefixtures('session')
async def test_bind_invalid_password_or_user(
    session: AsyncSession,
    ldap_session: LDAPSession,
    container: AsyncContainer,
) -> None:
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

    async with container(scope=Scope.REQUEST) as container:
        handler = await resolve_deps(bind.handle, container)
        result = await anext(handler())

    assert result == bad_response
    assert ldap_session.user is None

    bind = BindRequest(
        version=0,
        name='user1',
        AuthenticationChoice=SimpleAuthentication(password='password'),  # noqa
    )

    # async with container(scope=Scope.REQUEST) as container:
    handler = await resolve_deps(bind.handle, container)
    result = await anext(handler())

    assert result == bad_response
    assert ldap_session.user is None


@pytest.mark.asyncio()
@pytest.mark.usefixtures('session')
async def test_anonymous_bind(
    ldap_session: LDAPSession,
    container: AsyncContainer,
) -> None:
    """Test anonymous."""
    bind = BindRequest(
        version=0,
        name='',
        AuthenticationChoice=SimpleAuthentication(password=''),  # noqa
    )
    async with container(scope=Scope.REQUEST) as container:
        handler = await resolve_deps(bind.handle, container)
        result = await anext(handler())
    assert result == BindResponse(result_code=LDAPCodes.SUCCESS)
    assert ldap_session.user is None


@pytest.mark.asyncio()
async def test_anonymous_unbind(ldap_session: LDAPSession) -> None:
    """Test anonymous call."""
    ldap_session.delete_user = AsyncMock()  # type: ignore
    with pytest.raises(StopAsyncIteration):
        await anext(UnbindRequest().handle(ldap_session))
    assert ldap_session.user is None
    ldap_session.delete_user.assert_called()


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap3_bind(
        ldap_client: Connection,
        event_loop: BaseEventLoop,
        creds: TestCreds) -> None:
    """Test ldap3 bind."""
    assert not ldap_client.bound

    result = await event_loop.run_in_executor(None, ldap_client.bind)
    assert result
    assert ldap_client.bound

    result = await event_loop.run_in_executor(
        None, partial(ldap_client.rebind, user=creds.un, password=creds.pw))
    assert result
    assert ldap_client.bound

    result = await event_loop.run_in_executor(None, ldap_client.unbind)
    assert not ldap_client.bound


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap3_bind_sasl_plain(
        ldap_client: Connection,
        event_loop: BaseEventLoop,
        creds: TestCreds) -> None:
    """Test ldap3 bind."""
    assert not ldap_client.bound

    result = await event_loop.run_in_executor(
        None, ldap_client.rebind, None, None, SASL, PLAIN, (None, creds.un,
                                                            creds.pw),
    )
    assert result
    assert ldap_client.bound
