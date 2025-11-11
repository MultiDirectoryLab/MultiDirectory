"""DNS service router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import Depends
from fastapi.routing import APIRouter

from api.auth import verify_auth
from api.main.adapters.dns import DNSFastAPIAdapter
from api.main.schema import (
    DNSServiceForwardZoneCheckRequest,
    DNSServiceRecordCreateRequest,
    DNSServiceRecordDeleteRequest,
    DNSServiceRecordUpdateRequest,
    DNSServiceReloadZoneRequest,
    DNSServiceSetupRequest,
    DNSServiceZoneCreateRequest,
    DNSServiceZoneDeleteRequest,
    DNSServiceZoneUpdateRequest,
)
from ldap_protocol.dns import (
    DNSForwardServerStatus,
    DNSForwardZone,
    DNSRecords,
    DNSServerParam,
    DNSZone,
)

dns_router = APIRouter(
    prefix="/dns",
    tags=["DNS_SERVICE"],
    dependencies=[Depends(verify_auth)],
    route_class=DishkaRoute,
)


@dns_router.post("/record")
async def create_record(
    data: DNSServiceRecordCreateRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Create DNS record with given params."""
    await adapter.create_record(data)


@dns_router.delete("/record")
async def delete_single_record(
    data: DNSServiceRecordDeleteRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Delete DNS record with given params."""
    await adapter.delete_record(data)


@dns_router.patch("/record")
async def update_record(
    data: DNSServiceRecordUpdateRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Update DNS record with given params."""
    await adapter.update_record(data)


@dns_router.get("/record")
async def get_all_records(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSRecords]:
    """Get all DNS records of current zone."""
    return await adapter.get_all_records()


@dns_router.get("/status")
async def get_dns_status(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> dict[str, str | None]:
    """Get DNS service status."""
    return await adapter.get_dns_status()


@dns_router.post("/setup")
async def setup_dns(
    data: DNSServiceSetupRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Set up DNS service."""
    await adapter.setup_dns(data)


@dns_router.get("/zone")
async def get_dns_zone(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSZone]:
    """Get all DNS records of all zones."""
    return await adapter.get_dns_zone()


@dns_router.get("/zone/forward")
async def get_forward_dns_zones(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSForwardZone]:
    """Get list of DNS forward zones with forwarders."""
    return await adapter.get_forward_dns_zones()


@dns_router.post("/zone")
async def create_zone(
    data: DNSServiceZoneCreateRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Create new DNS zone."""
    await adapter.create_zone(data)


@dns_router.patch("/zone")
async def update_zone(
    data: DNSServiceZoneUpdateRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Update DNS zone with given params."""
    await adapter.update_zone(data)


@dns_router.delete("/zone")
async def delete_zone(
    data: DNSServiceZoneDeleteRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Delete DNS zone."""
    await adapter.delete_zone(data)


@dns_router.post("/forward_check")
async def check_dns_forward_zone(
    data: DNSServiceForwardZoneCheckRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSForwardServerStatus]:
    """Check given DNS forward zone for availability."""
    return await adapter.check_dns_forward_zone(data)


@dns_router.get("/zone/reload/")
async def reload_zone(
    data: DNSServiceReloadZoneRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Reload given DNS zone."""
    await adapter.reload_zone(data)


@dns_router.patch("/server/options")
async def update_server_options(
    data: list[DNSServerParam],
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Update DNS server options."""
    await adapter.update_server_options(data)


@dns_router.get("/server/options")
async def get_server_options(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSServerParam]:
    """Get list of modifiable DNS server params."""
    return await adapter.get_server_options()


@dns_router.get("/server/restart")
async def restart_server(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Restart entire DNS server."""
    await adapter.restart_server()
