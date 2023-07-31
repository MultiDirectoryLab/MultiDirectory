import pytest

from app.ldap.dialogue import Session
from app.ldap.ldap_requests import (
    BindRequest,
    BindResponse,
    LDAPCodes,
    SimpleAuthentication,
)
from app.models.ldap3 import Directory, User
from app.security import get_password_hash


@pytest.mark.asyncio()
async def test_bind_ok(session):
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
        AuthenticationChoice=SimpleAuthentication(password='password'),
    )

    async for result in bind.handle(ldap_session, session):
        assert result == BindResponse(result_code=LDAPCodes.SUCCESS)
