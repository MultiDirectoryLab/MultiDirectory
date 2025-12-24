from .base import (
    DNS_MANAGER_IP_ADDRESS_NAME,
    DNS_MANAGER_STATE_NAME,
    DNS_MANAGER_ZONE_NAME,
    AbstractDNSManager,
    DNSForwardServerStatus,
    DNSForwardZone,
    DNSManagerSettings,
    DNSNotImplementedError,
    DNSRecords,
    DNSServerParam,
    DNSServerParamName,
    DNSZone,
    DNSZoneParam,
    DNSZoneParamName,
    DNSZoneType,
)
from .dns_gateway import DNSStateGateway
from .enums import DNSManagerState
from .exceptions import DNSConnectionError, DNSError
from .powerdns import PowerDNSManager
from .remote import RemoteDNSManager
from .selfhosted import SelfHostedDNSManager
from .stub import StubDNSManager


async def get_dns_manager_class(
    dns_state_gateway: DNSStateGateway,
) -> type[AbstractDNSManager]:
    """Get DNS manager class."""
    dns_state = await dns_state_gateway.get_dns_state()
    if dns_state == DNSManagerState.SELFHOSTED:
        return PowerDNSManager
    elif dns_state == DNSManagerState.HOSTED:
        return RemoteDNSManager
    return StubDNSManager


__all__ = [
    "get_dns_manager_class",
    "AbstractDNSManager",
    "PowerDNSManager",
    "RemoteDNSManager",
    "SelfHostedDNSManager",
    "StubDNSManager",
    "DNSStateGateway",
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
    "DNSNotImplementedError",
    "DNSError",
]
