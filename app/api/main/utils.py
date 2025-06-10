"""Common utils for ldap api."""

from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Depends

from api.auth import get_current_user
from ldap_protocol.dialogue import LDAPSession, UserSchema


@inject
async def get_ldap_session(
    ldap_session: FromDishka[LDAPSession],
    user: Annotated[UserSchema, Depends(get_current_user)],
) -> LDAPSession:
    """Create LDAP session.

    Args:
        ldap_session (FromDishka[LDAPSession]): LDAP session.
        user (UserSchema): Current user.

    Returns:
        LDAPSession: LDAP session with user set.
    """
    await ldap_session.set_user(user)
    return ldap_session
