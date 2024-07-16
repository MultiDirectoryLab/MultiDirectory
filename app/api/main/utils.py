"""Common utils for ldap api."""

from typing import Annotated, AsyncIterator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import User, get_current_user
from config import Settings, get_settings
from ldap_protocol.dialogue import Session as LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, get_kerberos_class
from models.database import get_session


async def get_kadmin(
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
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
    kadmin: Annotated[AbstractKadmin, Depends(get_kadmin)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AsyncIterator[LDAPSession]:
    """Create LDAP session."""
    return LDAPSession(user=user, settings=settings, kadmin=kadmin)
