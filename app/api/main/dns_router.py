"""DNS service router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from api.auth import get_current_user
from api.main.schema import (
    DNSServiceForwardZoneCheckRequest,
    DNSServiceRecordCreateRequest,
    DNSServiceRecordDeleteRequest,
    DNSServiceRecordUpdateRequest,
    DNSServiceSetupRequest,
    DNSServiceZoneCreateRequest,
    DNSServiceZoneDeleteRequest,
    DNSServiceZoneUpdateRequest,
)
from config import Settings
from ldap_protocol.dns import (
    AbstractDNSManager,
    DNSForwardServerStatus,
    DNSForwardZone,
    DNSManagerSettings,
    DNSRecords,
    DNSServerParam,
    DNSZone,
    get_dns_state,
    set_dns_manager_state,
)

dns_router = APIRouter(
    prefix="/dns",
    tags=["DNS_SERVICE"],
    dependencies=[Depends(get_current_user)],
    route_class=DishkaRoute,
)


@dns_router.post("/record")
async def create_record(
    data: DNSServiceRecordCreateRequest,
    dns_manager: FromDishka[AbstractDNSManager],
) -> None:
    """Create DNS record with given params."""
    await dns_manager.create_record(
        data.record_name,
        data.record_value,
        data.record_type,
        data.ttl,
        zone_name=data.zone_name,
    )


@dns_router.delete("/record")
async def delete_single_record(
    data: DNSServiceRecordDeleteRequest,
    dns_manager: FromDishka[AbstractDNSManager],
) -> None:
    """Delete DNS record with given params."""
    await dns_manager.delete_record(
        data.record_name,
        data.record_value,
        data.record_type,
        zone_name=data.zone_name,
    )


@dns_router.patch("/record")
async def update_record(
    data: DNSServiceRecordUpdateRequest,
    dns_manager: FromDishka[AbstractDNSManager],
) -> None:
    """Update DNS record with given params."""
    await dns_manager.update_record(
        data.record_name,
        data.record_value,
        data.record_type,
        data.ttl,
        zone_name=data.zone_name,
    )


@dns_router.get("/record")
async def get_all_records(
    dns_manager: FromDishka[AbstractDNSManager],
) -> list[DNSRecords]:
    """Get all DNS records of current zone."""
    return await dns_manager.get_all_records()


@dns_router.get("/status")
async def get_dns_status(
    session: FromDishka[AsyncSession],
    dns_settings: FromDishka[DNSManagerSettings],
) -> dict[str, str | None]:
    """Get DNS service status."""
    state = await get_dns_state(session)
    return {
        "dns_status": state,
        "zone_name": dns_settings.zone_name,
        "dns_server_ip": dns_settings.dns_server_ip,
    }


@dns_router.post("/setup")
async def setup_dns(
    data: DNSServiceSetupRequest,
    dns_manager: FromDishka[AbstractDNSManager],
    session: FromDishka[AsyncSession],
    settings: FromDishka[Settings],
) -> None:
    """Set up DNS service.

    Create zone file, get TSIG key, reload DNS server if selfhosted.
    """
    dns_ip_address = (
        data.dns_ip_address
        if data.dns_ip_address is not None and len(data.dns_ip_address)
        else settings.DNS_BIND_HOST
    )

    tsig_key = data.tsig_key

    try:
        await dns_manager.setup(
            session=session,
            dns_status=data.dns_status,
            domain=data.domain,
            dns_ip_address=dns_ip_address,
            tsig_key=tsig_key,
        )
    except Exception as e:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, e)

    await set_dns_manager_state(session, data.dns_status)
    await session.commit()


@dns_router.get("/zone")
async def get_dns_zone(
    dns_manager: FromDishka[AbstractDNSManager],
) -> list[DNSZone]:
    """Get all DNS records of all zones."""
    return await dns_manager.get_all_zones_records()


@dns_router.get("/zone/forward")
async def get_forward_dns_zones(
    dns_manager: FromDishka[AbstractDNSManager],
) -> list[DNSForwardZone]:
    """Get list of DNS forward zones with forwarders."""
    return await dns_manager.get_forward_zones()


@dns_router.post("/zone")
async def create_zone(
    data: DNSServiceZoneCreateRequest,
    dns_manager: FromDishka[AbstractDNSManager],
) -> None:
    """Create new DNS zone."""
    await dns_manager.create_zone(
        data.zone_name,
        data.zone_type,
        data.params,
    )


@dns_router.patch("/zone")
async def update_zone(
    data: DNSServiceZoneUpdateRequest,
    dns_manager: FromDishka[AbstractDNSManager],
) -> None:
    """Update DNS zone with given params."""
    await dns_manager.update_zone(
        data.zone_name,
        data.params,
    )


@dns_router.delete("/zone")
async def delete_zone(
    data: DNSServiceZoneDeleteRequest,
    dns_manager: FromDishka[AbstractDNSManager],
) -> None:
    """Delete DNS zone."""
    await dns_manager.delete_zone(data.zone_names)


@dns_router.post("/forward_check")
async def check_dns_forward_zone(
    data: DNSServiceForwardZoneCheckRequest,
    dns_manager: FromDishka[AbstractDNSManager],
) -> list[DNSForwardServerStatus]:
    """Check given DNS forward zone for availability."""
    return [
        await dns_manager.check_forward_dns_server(dns_server_ip)
        for dns_server_ip in data.dns_server_ips
    ]


@dns_router.get("/zone/reload/{zone_name}")
async def reload_zone(
    zone_name: str,
    dns_manager: FromDishka[AbstractDNSManager],
) -> None:
    """Reload given DNS zone."""
    await dns_manager.reload_zone(zone_name)


@dns_router.patch("/server/options")
async def update_server_options(
    data: list[DNSServerParam],
    dns_manager: FromDishka[AbstractDNSManager],
) -> None:
    """Update DNS server options."""
    await dns_manager.update_server_options(data)


@dns_router.get("/server/options")
async def get_server_options(
    dns_manager: FromDishka[AbstractDNSManager],
) -> list[DNSServerParam]:
    """Get list of modifiable DNS server params."""
    return await dns_manager.get_server_options()


@dns_router.get("/server/restart")
async def restart_server(
    dns_manager: FromDishka[AbstractDNSManager],
) -> None:
    """Restart entire DNS server."""
    await dns_manager.restart_server()
