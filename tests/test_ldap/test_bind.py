"""Test bind ldap3 + white case.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from asyncio import BaseEventLoop
from functools import partial
from unittest.mock import AsyncMock, Mock

import gssapi
import pytest
from dishka import AsyncContainer, Scope
from ldap3 import PLAIN, SASL, Connection
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.dependency import resolve_deps
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.ldap_requests.bind import (
    BindRequest,
    BindResponse,
    LDAPCodes,
    SaslGSSAPIAuthentication,
    SimpleAuthentication,
    UnbindRequest,
)
from ldap_protocol.user_account_control import UserAccountControlFlag
from models import Attribute, Directory, User
from security import get_password_hash
from tests.conftest import MutePolicyBindRequest, TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_bind_ok_and_unbind(
    session: AsyncSession,
    ldap_session: LDAPSession,
    settings: Settings,
    kadmin: AbstractKadmin,
    creds: TestCreds,
) -> None:
    """Test ok bind."""
    bind = MutePolicyBindRequest(
        version=0,
        name=creds.un,
        AuthenticationChoice=SimpleAuthentication(password="password"),  # noqa
    )

    result = await anext(
        bind.handle(
            session,
            ldap_session,
            kadmin,
            settings,
            None,  # type: ignore
        ),
    )
    assert result == BindResponse(result_code=LDAPCodes.SUCCESS)
    assert ldap_session.user
    assert ldap_session.user.sam_accout_name == creds.un

    with pytest.raises(StopAsyncIteration):
        await anext(UnbindRequest().handle(ldap_session))
    assert ldap_session.user is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_gssapi_bind_in_progress(
    creds: TestCreds,
    container: AsyncContainer,
) -> None:
    """Test first step gssapi bind."""
    mock_security_context = Mock(spec=gssapi.SecurityContext)
    mock_security_context.step.return_value = b"response_ticket"
    mock_security_context.complete = False

    async def mock_init_security_context(
        session: AsyncSession,
        settings: Settings,
    ) -> None:
        auth_choice._ldap_session.gssapi_security_context = (
            mock_security_context
        )

    auth_choice = SaslGSSAPIAuthentication(ticket=b"ticket")
    auth_choice._init_security_context = mock_init_security_context  # type: ignore

    bind = BindRequest(
        version=0,
        name=creds.un,
        AuthenticationChoice=auth_choice,
    )

    async with container(scope=Scope.REQUEST) as container:
        handler = await resolve_deps(bind.handle, container)
        result = await anext(handler())  # type: ignore
        assert result == BindResponse(
            result_code=LDAPCodes.SASL_BIND_IN_PROGRESS,
            serverSaslCreds=b"response_ticket",
        )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_gssapi_bind_missing_credentials(
    creds: TestCreds,
    container: AsyncContainer,
) -> None:
    """Test gssapi bind with missing credentials."""
    bind = BindRequest(
        version=0,
        name=creds.un,
        AuthenticationChoice=SaslGSSAPIAuthentication(),
    )

    async with container(scope=Scope.REQUEST) as container:
        handler = await resolve_deps(bind.handle, container)
        with pytest.raises(gssapi.exceptions.MissingCredentialsError):
            await anext(handler())  # type: ignore


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_gssapi_bind_ok(
    creds: TestCreds,
    container: AsyncContainer,
) -> None:
    """Test gssapi bind ok."""
    mock_security_context = Mock(spec=gssapi.SecurityContext)
    mock_security_context.step.return_value = b"server_ticket"
    mock_security_context.complete = False
    mock_security_context.initiator_name = f"{creds.un}@domain"
    mock_security_context.wrap.return_value = (
        gssapi.raw.named_tuples.WrapResult(
            message=b"\x01\x00\x04\x00",
            encrypted=False,
        )
    )
    mock_security_context.unwrap.return_value = (
        gssapi.raw.named_tuples.UnwrapResult(
            message=b"\x01\x00\x04\x00",
            encrypted=False,
            qop=0,
        )
    )

    async def mock_init_security_context(
        session: AsyncSession,
        settings: Settings,
    ) -> None:
        auth_choice._ldap_session.gssapi_security_context = (
            mock_security_context
        )

    auth_choice = SaslGSSAPIAuthentication(ticket=b"client_ticket")
    auth_choice._init_security_context = mock_init_security_context  # type: ignore

    first_bind = BindRequest(
        version=0,
        name=creds.un,
        AuthenticationChoice=auth_choice,
    )

    second_bind = BindRequest(
        version=0,
        name=creds.un,
        AuthenticationChoice=SaslGSSAPIAuthentication(),
    )

    third_bind = MutePolicyBindRequest(
        version=0,
        name=creds.un,
        AuthenticationChoice=SaslGSSAPIAuthentication(
            ticket=b"wrap_client_request",
        ),
    )

    async with container(scope=Scope.REQUEST) as container:
        handler = await resolve_deps(first_bind.handle, container)
        result = await anext(handler())  # type: ignore
        assert result == BindResponse(
            result_code=LDAPCodes.SASL_BIND_IN_PROGRESS,
            serverSaslCreds=b"server_ticket",
        )

        mock_security_context.complete = True

        handler = await resolve_deps(second_bind.handle, container)
        result = await anext(handler())  # type: ignore
        assert result == BindResponse(
            result_code=LDAPCodes.SASL_BIND_IN_PROGRESS,
            serverSaslCreds=b"\x01\x00\x04\x00",
        )

        handler = await resolve_deps(third_bind.handle, container)
        result = await anext(handler())  # type: ignore
        assert result == BindResponse(
            result_code=LDAPCodes.SUCCESS,
        )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_bind_invalid_password_or_user(
    session: AsyncSession,
    ldap_session: LDAPSession,
    container: AsyncContainer,
) -> None:
    """Test invalid password bind."""
    directory = Directory(
        name="user0",
        object_class="",
        path=["cn=user0", "ou=users", "dc=md", "dc=test"],
        rdname="cn",
    )
    user = User(
        sam_accout_name="user0",
        user_principal_name="user0",
        mail="user0",
        display_name="user0",
        password=get_password_hash("password"),
        directory=directory,
    )
    user_account_control_attribute = Attribute(
        directory=directory,
        name="userAccountControl",
        value=str(UserAccountControlFlag.NORMAL_ACCOUNT),
        bvalue=None,
    )
    session.add_all([directory, user, user_account_control_attribute])
    await session.commit()

    bind = BindRequest(
        version=0,
        name="user0",
        AuthenticationChoice=SimpleAuthentication(password="fail"),  # noqa
    )

    bad_response = BindResponse(
        result_code=LDAPCodes.INVALID_CREDENTIALS,
        matchedDN="",
        errorMessage=(
            "80090308: LdapErr: DSID-0C09030B, "
            "comment: AcceptSecurityContext error, "
            "data 52e, v893"
        ),
    )

    async with container(scope=Scope.REQUEST) as container:
        handler = await resolve_deps(bind.handle, container)
        result = await anext(handler())  # type: ignore

    assert result == bad_response
    assert ldap_session.user is None

    bind = BindRequest(
        version=0,
        name="user1",
        AuthenticationChoice=SimpleAuthentication(password="password"),  # noqa
    )

    # async with container(scope=Scope.REQUEST) as container:
    handler = await resolve_deps(bind.handle, container)
    result = await anext(handler())  # type: ignore

    assert result == bad_response
    assert ldap_session.user is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_anonymous_bind(
    ldap_session: LDAPSession,
    container: AsyncContainer,
) -> None:
    """Test anonymous."""
    bind = BindRequest(
        version=0,
        name="",
        AuthenticationChoice=SimpleAuthentication(password=""),
    )
    async with container(scope=Scope.REQUEST) as container:
        handler = await resolve_deps(bind.handle, container)
        result = await anext(handler())  # type: ignore
    assert result == BindResponse(result_code=LDAPCodes.SUCCESS)
    assert ldap_session.user is None


@pytest.mark.asyncio
async def test_anonymous_unbind(ldap_session: LDAPSession) -> None:
    """Test anonymous call."""
    ldap_session.delete_user = AsyncMock()  # type: ignore
    with pytest.raises(StopAsyncIteration):
        await anext(UnbindRequest().handle(ldap_session))
    assert ldap_session.user is None
    ldap_session.delete_user.assert_called()


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_ldap3_bind(
    ldap_client: Connection,
    event_loop: BaseEventLoop,
    creds: TestCreds,
) -> None:
    """Test ldap3 bind."""
    assert not ldap_client.bound

    result = await event_loop.run_in_executor(None, ldap_client.bind)
    assert result
    assert ldap_client.bound

    result = await event_loop.run_in_executor(
        None,
        partial(ldap_client.rebind, user=creds.un, password=creds.pw),
    )
    assert result
    assert ldap_client.bound

    result = await event_loop.run_in_executor(None, ldap_client.unbind)
    assert not ldap_client.bound


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_ldap3_bind_sasl_plain(
    ldap_client: Connection,
    event_loop: BaseEventLoop,
    creds: TestCreds,
) -> None:
    """Test ldap3 bind."""
    assert not ldap_client.bound

    result = await event_loop.run_in_executor(
        None,
        ldap_client.rebind,
        None,
        None,
        SASL,
        PLAIN,
        (None, creds.un, creds.pw),
    )
    assert result
    assert ldap_client.bound


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_bind_disabled_user(
    session: AsyncSession,
    ldap_session: LDAPSession,
    container: AsyncContainer,
) -> None:
    """Test disabled user bind."""
    directory = Directory(
        name="user0",
        object_class="",
        path=["cn=user0", "ou=users", "dc=md", "dc=test"],
        rdname="cn",
    )
    user = User(
        sam_accout_name="user0",
        user_principal_name="user0",
        mail="user0",
        display_name="user0",
        password=get_password_hash("password"),
        directory=directory,
    )
    user_account_control_attribute = Attribute(
        directory=directory,
        name="userAccountControl",
        value=str(UserAccountControlFlag.ACCOUNTDISABLE),
        bvalue=None,
    )
    session.add_all([directory, user, user_account_control_attribute])
    await session.commit()

    bind = BindRequest(
        version=0,
        name=user.sam_accout_name,
        AuthenticationChoice=SimpleAuthentication(password="password"),  # noqa
    )

    bad_response = BindResponse(
        result_code=LDAPCodes.INVALID_CREDENTIALS,
        matchedDn="",
        errorMessage=(
            "80090308: LdapErr: DSID-0C09030B, "
            "comment: AcceptSecurityContext error, "
            "data 533, v893"
        ),
    )

    async with container(scope=Scope.REQUEST) as container:
        handler = await resolve_deps(bind.handle, container)
        result = await anext(handler())  # type: ignore

    assert result == bad_response
    assert ldap_session.user is None
