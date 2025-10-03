from sqlalchemy.ext.asyncio import AsyncSession

from .base import AbstractKadmin
from .client import KerberosMDAPIClient
from .exceptions import KRBAPIError, KRBAPIPrincipalNotFoundError
from .stub import StubKadminMDADPIClient
from .utils import (
    KERBEROS_STATE_NAME,
    KerberosState,
    get_krb_server_state,
    set_state,
    unlock_principal,
)


async def get_kerberos_class(session: AsyncSession) -> type[AbstractKadmin]:
    """Get kerberos server state.

    :param AsyncSession session: db
    :return type[KerberosMDAPIClient] | type[StubKadminMDADPIClient]: api
    """
    if await get_krb_server_state(session) == KerberosState.READY:
        return KerberosMDAPIClient
    return StubKadminMDADPIClient


__all__ = [
    "get_kerberos_class",
    "KerberosMDAPIClient",
    "StubKadminMDADPIClient",
    "AbstractKadmin",
    "KerberosState",
    "KRBAPIError",
    "KRBAPIPrincipalNotFoundError",
    "unlock_principal",
    "KERBEROS_STATE_NAME",
    "set_state",
]
