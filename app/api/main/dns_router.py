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
    DNSServiceRecordCreateRequest,
    DNSServiceRecordDeleteRequest,
    DNSServiceRecordUpdateRequest,
    DNSServiceSetupRequest,
)
from config import Settings
from ldap_protocol.dns import (
    AbstractDNSManager,
    DNSManagerSettings,
    DNSManagerState,
    DNSRecords,
    get_dns_state,
    set_dns_manager_state,
)

dns_router = APIRouter(
    prefix='/dns',
    tags=['DNS_SERVICE'],
    dependencies=[Depends(get_current_user)],
    route_class=DishkaRoute,
)


@dns_router.post('/record')
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
async def get_all_records(
    dns_manager: FromDishka[AbstractDNSManager],
) -> list[DNSRecords]:
    """Get all DNS records of current zone."""
    return await dns_manager.get_all_records()


@dns_router.get('/status')
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
    conf_part = None
    dns_ip_address = data.dns_ip_address
    tsig_key = data.tsig_key

    if data.dns_status == DNSManagerState.SELFHOSTED:
        zone_file_template = settings.TEMPLATES.get_template("zone.template")
        zone_file = await zone_file_template.render_async(domain=data.domain)

        tmpl = settings.TEMPLATES.get_template(
            "named_conf_local_zone_part.template",
        )
        conf_part = await tmpl.render_async(domain=data.domain)

    try:
        await dns_manager.setup(
            session=session,
            settings=settings,
            domain=data.domain,
            dns_ip_address=dns_ip_address,
            zone_file=zone_file,
            tsig_key=tsig_key,
            named_conf_local_part=conf_part,
        )
    except Exception as e:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, e)

    await set_dns_manager_state(session, data.dns_status)
    await session.commit()
