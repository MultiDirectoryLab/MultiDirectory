"""Common utils for ldap api."""

from dishka import FromDishka
from dishka.integrations.fastapi import inject

from api.auth.adapters.identity import IdentityFastAPIAdapter
from ldap_protocol.dialogue import LDAPSession


@inject
async def get_ldap_session(
    ldap_session: FromDishka[LDAPSession],
    identity_adapter: FromDishka[IdentityFastAPIAdapter],
) -> LDAPSession:
    """Create LDAP session."""
    await ldap_session.set_user(await identity_adapter.get_current_user())
    return ldap_session
