"""Common utils for ldap api."""

from typing import Annotated, AsyncIterator

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Depends

from api.auth import User, get_current_user
from ldap_protocol.dialogue import LDAPSession


@inject
async def get_ldap_session(
    ldap_session: FromDishka[LDAPSession],
    user: Annotated[User, Depends(get_current_user)],
) -> AsyncIterator[LDAPSession]:
    """Create LDAP session."""
    await ldap_session.set_user(user)
    return ldap_session
