"""Common utils for ldap api."""

from typing import Annotated, AsyncIterator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import User, get_current_user
from config import Settings, get_settings
from ldap_protocol.dialogue import Session as LDAPSession
from ldap_protocol.kerberos import get_kerberos_class
from models.database import get_session


async def ldap_session(
    user: Annotated[User, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AsyncIterator[LDAPSession]:
    """Create LDAP session."""
    cls = await get_kerberos_class(session)
    async with cls.get_krb_ldap_client(settings) as kadmin:
        yield LDAPSession(user=user, settings=settings, kadmin=kadmin)
