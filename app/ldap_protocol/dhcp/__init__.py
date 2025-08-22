from sqlalchemy.ext.asyncio import AsyncSession

from .base import AbstractDHCPManager, DHCPManagerState
from .kea_dhcp import KeaDHCPManager
from .stub import StubDHCPManager
from .utils import get_dhcp_state


async def get_dhcp_manager_class(
    session: AsyncSession,
) -> type[AbstractDHCPManager]:
    """Get an instance of the DHCP manager."""
    dhcp_state = await get_dhcp_state(session)
    if dhcp_state == DHCPManagerState.KEA_DHCP:
        return KeaDHCPManager
    return StubDHCPManager


__all__ = [
    "AbstractDHCPManager",
    "KeaDHCPManager",
    "get_dhcp_manager_class",
]
