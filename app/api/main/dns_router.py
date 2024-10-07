"""DNS service router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import re
import socket
from typing import Annotated, Any, Optional

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Body, HTTPException, Depends
from fastapi.routing import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from api.auth import get_current_user
from config import Settings
from ldap_protocol.dns import (
    AbstractDNSManager,
    DNSAPIError,
    DNSManagerSettings,
    DNSManagerState,
    get_dns_state,
    set_dns_manager_state,
)

dns_router = APIRouter(
    prefix='/dns',
    tags=['DNS_SERVICE'],
    dependencies=[Depends(get_current_user)]
)


@dns_router.post('/record')
@inject
async def create_record(
    hostname: Annotated[str, Body()],
    ip: Annotated[str, Body()],
    record_type: Annotated[str, Body()],
    ttl: Annotated[int, Body()],
    dns_manager: FromDishka[AbstractDNSManager],
):
    """Create DNS record with given params."""
    try:
        await dns_manager.create_record(hostname, ip, record_type, ttl)
    except Exception as e:
        raise HTTPException(500, f"{e}")


@dns_router.delete('/record')
@inject
async def delete_single_record(
    hostname: Annotated[str, Body()],
    ip: Annotated[str, Body()],
    record_type: Annotated[str, Body()],
    dns_manager: FromDishka[AbstractDNSManager],
):
    """Delete DNS record with given params."""
    try:
        await dns_manager.delete_record(hostname, ip, record_type)
    except Exception:
        raise HTTPException(500, "DNS transaction failed")


@dns_router.patch('/record')
@inject
async def update_record(
    hostname: Annotated[str, Body()],
    ip: Annotated[str, Body()],
    record_type: Annotated[str, Body()],
    ttl: Annotated[int, Body()],
    dns_manager: FromDishka[AbstractDNSManager],
):
    """Update DNS record with given params."""
    try:
        await dns_manager.update_record(hostname, ip, record_type, ttl)
    except Exception as e:
        raise HTTPException(500, f"{e}")


@dns_router.get('/record')
@inject
async def get_all_records(
        dns_manager: FromDishka[AbstractDNSManager],
) -> list:
    """Get all DNS records of current zone."""
    try:
        return await dns_manager.get_all_records()
    except Exception as e:
        raise HTTPException(500, str(e))


@dns_router.get('/status')
@inject
async def get_dns_status(
    session: FromDishka[AsyncSession],
    dns_settings: FromDishka[DNSManagerSettings],
):
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
    dns_status: Annotated[str, Body()],
    domain: Annotated[str, Body()],
    dns_manager: FromDishka[AbstractDNSManager],
    dns_ip_address: Annotated[str | None, Body()],
    tsig_key: Annotated[str | None, Body()],
    session: FromDishka[AsyncSession],
    settings: FromDishka[Settings],
):
    """Set up DNS service.

    Create zone file, get TSIG key, reload DNS server if selfhosted.
    """
    zone_file = None
    named_conf_local_part = None

    if dns_status == DNSManagerState.SELFHOSTED:
        zone_file_template = settings.TEMPLATES.get_template("zone.template")
        zone_file = await zone_file_template.render_async(domain=domain)

        with open(settings.DNS_TSIG_KEY, "r") as f:
            key_file_content = f.read()

        tsig_key = re.findall(r"\ssecret \"(\S+)\"", key_file_content)[0]

        named_conf_local_part_template = settings.TEMPLATES.get_template(
            "named_conf_local_zone_part.template",
        )
        named_conf_local_part = await named_conf_local_part_template.render_async(
            domain=domain,
        )

        dns_ip_address = socket.gethostbyname(settings.DNS_BIND_HOST)

    try:
        await dns_manager.setup(
            session=session,
            settings=settings,
            domain=domain,
            dns_ip_address=dns_ip_address,
            zone_file=zone_file,
            tsig_key=tsig_key,
            named_conf_local_part=named_conf_local_part,
        )
    except DNSAPIError as e:
        raise HTTPException(status.HTTP_304_NOT_MODIFIED, e)

    await set_dns_manager_state(session, dns_status)
    await session.commit()
