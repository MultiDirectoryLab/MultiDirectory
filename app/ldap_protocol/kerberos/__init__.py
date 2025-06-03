from sqlalchemy.ext.asyncio import AsyncSession

from .base import (
    KERBEROS_STATE_NAME,
    AbstractKadmin,
    KerberosState,
    KRBAPIError,
)
from .client import KerberosMDAPIClient
from .stub import StubKadminMDADPIClient
from .utils import get_krb_server_state, set_state, unlock_principal


async def get_kerberos_class(session: AsyncSession) -> type[AbstractKadmin]:
    """Get kerberos server state.

    :param AsyncSession session: db
    :return type[KerberosMDAPIClient] | type[StubKadminMDADPIClient]: api
    """
    if await get_krb_server_state(session) == KerberosState.READY:
        return KerberosMDAPIClient
    return StubKadminMDADPIClient


__all__ = [
    "KERBEROS_STATE_NAME",
    "AbstractKadmin",
    "KRBAPIError",
    "KerberosMDAPIClient",
    "KerberosState",
    "StubKadminMDADPIClient",
    "get_kerberos_class",
    "set_state",
    "unlock_principal",
]
