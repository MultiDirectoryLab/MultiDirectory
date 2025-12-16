"""DNS service router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dns.exception import DNSException
from fastapi import Depends, status
from fastapi_error_map import rule
from fastapi_error_map.routing import ErrorAwareRouter

import ldap_protocol.dns.exceptions as dns_exc
from api.auth.utils import verify_auth
from api.error_routing import (
    ERROR_MAP_TYPE,
    DishkaErrorAwareRoute,
    DomainErrorTranslator,
)
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
from enums import DomainCodes
from ldap_protocol.dns import (
    DNSForwardServerStatus,
    DNSForwardZone,
    DNSRecords,
    DNSServerParam,
    DNSZone,
)

translator = DomainErrorTranslator(DomainCodes.DNS)


error_map: ERROR_MAP_TYPE = {
    dns_exc.DNSSetupError: rule(
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        translator=translator,
    ),
    dns_exc.DNSRecordCreateError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    dns_exc.DNSRecordUpdateError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    dns_exc.DNSRecordDeleteError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    dns_exc.DNSZoneCreateError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    dns_exc.DNSZoneUpdateError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    dns_exc.DNSZoneDeleteError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    dns_exc.DNSUpdateServerOptionsError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    DNSException: rule(
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        translator=translator,
    ),
    dns_exc.DNSConnectionError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    dns_exc.DNSNotImplementedError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
}

dns_router = ErrorAwareRouter(
    prefix="/dns",
    tags=["DNS_SERVICE"],
    dependencies=[Depends(verify_auth)],
    route_class=DishkaErrorAwareRoute,
)


@dns_router.post("/record", error_map=error_map)
async def create_record(
    data: DNSServiceRecordCreateRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Create DNS record with given params."""
    await adapter.create_record(data)


@dns_router.delete("/record", error_map=error_map)
async def delete_single_record(
    data: DNSServiceRecordDeleteRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Delete DNS record with given params."""
    await adapter.delete_record(data)


@dns_router.patch("/record", error_map=error_map)
async def update_record(
    data: DNSServiceRecordUpdateRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Update DNS record with given params."""
    await adapter.update_record(data)


@dns_router.get("/record", error_map=error_map)
async def get_all_records(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSRecords]:
    """Get all DNS records of current zone."""
    return await adapter.get_all_records()


@dns_router.get("/status", error_map=error_map)
async def get_dns_status(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> dict[str, str | None]:
    """Get DNS service status."""
    return await adapter.get_dns_status()


@dns_router.post("/setup", error_map=error_map)
async def setup_dns(
    data: DNSServiceSetupRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Set up DNS service."""
    await adapter.setup_dns(data)


@dns_router.get("/zone", error_map=error_map)
async def get_dns_zone(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSZone]:
    """Get all DNS records of all zones."""
    return await adapter.get_dns_zone()


@dns_router.get("/zone/forward", error_map=error_map)
async def get_forward_dns_zones(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSForwardZone]:
    """Get list of DNS forward zones with forwarders."""
    return await adapter.get_forward_dns_zones()


@dns_router.post(
    "/zone",
    error_map=error_map,
    warn_on_unmapped=False,
    default_client_error_translator=translator,
)
async def create_zone(
    data: DNSServiceZoneCreateRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Create new DNS zone."""
    await adapter.create_zone(data)


@dns_router.patch("/zone", error_map=error_map)
async def update_zone(
    data: DNSServiceZoneUpdateRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Update DNS zone with given params."""
    await adapter.update_zone(data)


@dns_router.delete("/zone", error_map=error_map)
async def delete_zone(
    data: DNSServiceZoneDeleteRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Delete DNS zone."""
    await adapter.delete_zone(data)


@dns_router.post("/forward_check", error_map=error_map)
async def check_dns_forward_zone(
    data: DNSServiceForwardZoneCheckRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSForwardServerStatus]:
    """Check given DNS forward zone for availability."""
    return await adapter.check_dns_forward_zone(data)


@dns_router.get("/zone/reload/", error_map=error_map)
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
