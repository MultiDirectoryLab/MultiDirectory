from sqlalchemy.ext.asyncio import AsyncSession

from .base import (
    DNS_MANAGER_IP_ADDRESS_NAME,
    DNS_MANAGER_STATE_NAME,
    DNS_MANAGER_ZONE_NAME,
    AbstractDNSManager,
    DNSConnectionError,
    DNSForwardServerStatus,
    DNSForwardZone,
    DNSManagerSettings,
    DNSManagerState,
    DNSRecords,
    DNSServerParam,
    DNSServerParamName,
    DNSZone,
    DNSZoneParam,
    DNSZoneParamName,
    DNSZoneType,
)
from .remote import RemoteDNSManager
from .selfhosted import SelfHostedDNSManager
from .stub import StubDNSManager
from .utils import (
    get_dns_manager_settings,
    get_dns_state,
    resolve_dns_server_ip,
    set_dns_manager_state,
)


async def get_dns_manager_class(
    session: AsyncSession,
) -> type[AbstractDNSManager]:
    """Get DNS manager class."""
    dns_state = await get_dns_state(session)
    if dns_state == DNSManagerState.SELFHOSTED:
        return SelfHostedDNSManager
    elif dns_state == DNSManagerState.HOSTED:
        return RemoteDNSManager
    return StubDNSManager


__all__ = [
    "get_dns_manager_class",
    "AbstractDNSManager",
    "RemoteDNSManager",
    "SelfHostedDNSManager",
    "StubDNSManager",
    "get_dns_state",
    "set_dns_manager_state",
    "get_dns_manager_settings",
    "resolve_dns_server_ip",
    "DNSForwardServerStatus",
    "DNSForwardZone",
    "DNSManagerSettings",
    "DNSRecords",
    "DNSServerParam",
    "DNSZone",
    "DNSZoneParam",
    "DNSZoneType",
    "DNSServerParamName",
    "DNSZoneParamName",
    "DNSConnectionError",
    "DNS_MANAGER_IP_ADDRESS_NAME",
    "DNS_MANAGER_ZONE_NAME",
    "DNS_MANAGER_STATE_NAME",
]
