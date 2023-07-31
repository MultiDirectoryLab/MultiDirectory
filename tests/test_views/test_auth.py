import pytest

from app.ldap.dialogue import Session
from app.ldap.ldap_requests import (
    BindRequest,
    BindResponse,
    LDAPCodes,
    SimpleAuthentication,
    UnbindRequest,
)
from app.models.ldap3 import Directory, User
from app.security import get_password_hash


@pytest.mark.asyncio()
async def test_bind_ok_and_unbind(session):
    """Test ok bind."""
    ldap_session = Session()
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

    bind = BindRequest(
        version=0,
        name='user0',
        AuthenticationChoice=SimpleAuthentication(password='password'),  # noqa
    )

    result = await anext(bind.handle(ldap_session, session))
    assert result == BindResponse(result_code=LDAPCodes.SUCCESS)
    assert ldap_session.user.sam_accout_name == user.sam_accout_name

    with pytest.raises(StopAsyncIteration):
        await anext(UnbindRequest().handle(ldap_session, session))
    assert ldap_session.user is None


@pytest.mark.asyncio()
async def test_bind_invalid_password_or_user(session):
    """Test invalid password bind."""
    ldap_session = Session()
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
async def test_anonymous_bind(session):
    """Test anonymous."""
    ldap_session = Session()
    bind = BindRequest(
        version=0,
        name='',
        AuthenticationChoice=SimpleAuthentication(password=''),  # noqa
    )

    result = await anext(bind.handle(ldap_session, session))
    assert result == BindResponse(result_code=LDAPCodes.SUCCESS)
    assert ldap_session.user is None
