"""Common utils for ldap api."""

from typing import Annotated, AsyncIterator

from dishka import FromDishka
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import User, get_current_user
from config import Settings
from ldap_protocol.dialogue import LDAPSession as LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, get_kerberos_class


async def get_kadmin(
    session: FromDishka[AsyncSession],
    settings: FromDishka[Settings],
) -> AsyncIterator[AbstractKadmin]:
    """Get kerberos class.

    :param Annotated[AsyncSession, Depends session: db
    :return AbstractKadmin: wrapper
    """
    cls = await get_kerberos_class(session)
    async with cls.get_krb_ldap_client(settings) as kadmin:
        yield kadmin


async def get_ldap_session(
    user: Annotated[User, Depends(get_current_user)],
) -> AsyncIterator[LDAPSession]:
    """Create LDAP session."""
    return LDAPSession(user=user)
