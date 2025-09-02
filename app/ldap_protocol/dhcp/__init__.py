from .base import AbstractDHCPManager, DHCPAPIRepository
from .dhcp_manager_repository import DHCPManagerRepository
from .enums import DHCPManagerState
from .kea_dhcp_manager import KeaDHCPManager
from .kea_dhcp_repository import KeaDHCPAPIRepository
from .stub import StubDHCPAPIRepository, StubDHCPManager


async def get_dhcp_manager_class(
    dhcp_state: DHCPManagerState,
) -> type[AbstractDHCPManager]:
    """Get an instance of the DHCP manager."""
    if dhcp_state == DHCPManagerState.KEA_DHCP:
        return KeaDHCPManager
    return StubDHCPManager


async def get_dhcp_api_repository_class(
    dhcp_state: DHCPManagerState,
) -> type[DHCPAPIRepository]:
    """Get an instance of the DHCP API repository."""
    if dhcp_state == DHCPManagerState.KEA_DHCP:
        return KeaDHCPAPIRepository
    return StubDHCPAPIRepository


__all__ = [
    "AbstractDHCPManager",
    "KeaDHCPManager",
    "get_dhcp_manager_class",
    "DHCPAPIRepository",
    "DHCPManagerRepository",
]
