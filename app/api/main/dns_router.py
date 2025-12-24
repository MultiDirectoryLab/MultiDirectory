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
    DNSServiceForwardZoneRequest,
    DNSServiceMasterZoneRequest,
    DNSServiceRecordCreateRequest,
    DNSServiceRecordDeleteRequest,
    DNSServiceRecordUpdateRequest,
    DNSServiceSetStateRequest,
    DNSServiceSetupRequest,
    DNSServiceZoneDeleteRequest,
)
from enums import DomainCodes
from ldap_protocol.dns import DNSForwardServerStatus
from ldap_protocol.dns.dto import (
    DNSForwardZoneDTO,
    DNSMasterZoneDTO,
    DNSRRSetDTO,
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
    tags=["DNS Service"],
    dependencies=[Depends(verify_auth)],
    route_class=DishkaErrorAwareRoute,
)


@dns_router.post("/record/{zone_id}", error_map=error_map)
async def create_record(
    zone_id: str,
    data: DNSServiceRecordCreateRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Create DNS record with given params."""
    await adapter.create_record(zone_id, data)


@dns_router.get("/record/{zone_id}", error_map=error_map)
async def get_all_records(
    zone_id: str,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSRRSetDTO]:
    """Get all DNS records of current zone."""
    return await adapter.get_records(zone_id)


@dns_router.patch("/record/{zone_id}", error_map=error_map)
async def update_record(
    zone_id: str,
    data: DNSServiceRecordUpdateRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Update DNS record with given params."""
    await adapter.update_record(zone_id, data)


@dns_router.delete("/record/{zone_id}", error_map=error_map)
async def delete_single_record(
    zone_id: str,
    data: DNSServiceRecordDeleteRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Delete DNS record with given params."""
    await adapter.delete_record(zone_id, data)


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


@dns_router.post("/state", error_map=error_map)
async def set_dns_state(
    data: DNSServiceSetStateRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Set DNS manager state."""
    await adapter.set_dns_state(data)


@dns_router.post("/zone/forward", error_map=error_map)
async def create_forward_zone(
    data: DNSServiceForwardZoneRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Create new forward DNS zone."""
    return await adapter.create_forward_zone(data)


@dns_router.get("/zone/forward", error_map=error_map)
async def get_forward_dns_zones(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSForwardZoneDTO]:
    """Get list of DNS forward zones with forwarders."""
    return await adapter.get_dns_forward_zones()


@dns_router.patch("/zone/forward", error_map=error_map)
async def update_forward_zone(
    data: DNSServiceForwardZoneRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Update forward DNS zone with given params."""
    await adapter.update_forward_zone(data)


@dns_router.delete("/zone/forward", error_map=error_map)
async def delete_forward_zone(
    data: DNSServiceZoneDeleteRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Delete DNS forward zone."""
    await adapter.delete_forward_zones(data)


@dns_router.post(
    "/zone",
    error_map=error_map,
    warn_on_unmapped=False,
    default_client_error_translator=translator,
)
async def create_zone(
    data: DNSServiceMasterZoneRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> None:
    """Create new DNS zone."""
    await adapter.create_zone(data)


@dns_router.get("/zone", error_map=error_map)
async def get_dns_zones(
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSMasterZoneDTO]:
    """Get all DNS records of all zones."""
    return await adapter.get_dns_master_zones()


@dns_router.patch("/zone", error_map=error_map)
async def update_zone(
    data: DNSServiceMasterZoneRequest,
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
    await adapter.delete_zones(data)


@dns_router.post("/forward_check", error_map=error_map)
async def check_dns_forward_zone(
    data: DNSServiceForwardZoneCheckRequest,
    adapter: FromDishka[DNSFastAPIAdapter],
) -> list[DNSForwardServerStatus]:
    """Check given DNS forward zone for availability."""
    return await adapter.check_dns_forward_zone(data)
