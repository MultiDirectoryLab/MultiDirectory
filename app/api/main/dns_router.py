"""DNS service router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from api.auth import get_current_user
from api.main.schema import DNSServiceSetupRequest, DNSServiceRecordCreateRequest, DNSServiceRecordDeleteRequest, \
    DNSServiceRecordUpdateRequest
from config import Settings
from ldap_protocol.dns import (
    AbstractDNSManager,
    DNSAPIError,
    DNSManagerSettings,
    DNSManagerState,
    get_dns_state,
    resolve_dns_server_ip,
    set_dns_manager_state,
)

dns_router = APIRouter(
    prefix='/dns',
    tags=['DNS_SERVICE'],
    dependencies=[Depends(get_current_user)],
)


@dns_router.post('/record')
@inject
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
    )


@dns_router.delete('/record')
@inject
async def delete_single_record(
    data: DNSServiceRecordDeleteRequest,
    dns_manager: FromDishka[AbstractDNSManager],
) -> None:
    """Delete DNS record with given params."""
    await dns_manager.delete_record(
        data.record_name,
        data.record_value,
        data.record_type,
    )


@dns_router.patch('/record')
@inject
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
    )


@dns_router.get('/record')
@inject
async def get_all_records(
    dns_manager: FromDishka[AbstractDNSManager],
) -> list:
    """Get all DNS records of current zone."""
    return await dns_manager.get_all_records()


@dns_router.get('/status')
@inject
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


@dns_router.post('/setup')
@inject
async def setup_dns(
    data: DNSServiceSetupRequest,
    dns_manager: FromDishka[AbstractDNSManager],
    session: FromDishka[AsyncSession],
    settings: FromDishka[Settings],
) -> None:
    """Set up DNS service.

    Create zone file, get TSIG key, reload DNS server if selfhosted.
    """
    zone_file = None
    named_conf_local_part = None
    dns_ip_address = data.dns_ip_address
    tsig_key = data.tsig_key

    if data.dns_status == DNSManagerState.SELFHOSTED:
        zone_file_template = settings.TEMPLATES.get_template("zone.template")
        zone_file = await zone_file_template.render_async(domain=data.domain)

        named_conf_local_part_template = settings.TEMPLATES.get_template(
            "named_conf_local_zone_part.template",
        )
        named_conf_local_part = await named_conf_local_part_template.render_async(
            domain=data.domain,
        )

    try:
        await dns_manager.setup(
            session=session,
            settings=settings,
            domain=data.domain,
            dns_ip_address=dns_ip_address,
            zone_file=zone_file,
            tsig_key=tsig_key,
            named_conf_local_part=named_conf_local_part,
        )
    except DNSAPIError as e:
        raise HTTPException(status.HTTP_304_NOT_MODIFIED, e)

    await set_dns_manager_state(session, data.dns_status)
    await session.commit()
