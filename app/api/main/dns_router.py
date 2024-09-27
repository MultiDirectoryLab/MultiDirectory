"""DNS service router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from typing import List, Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Body, HTTPException
from fastapi.routing import APIRouter

from ldap_protocol.dns import DNSManager

dns_router = APIRouter(prefix='/dns', tags=['DNS_SERVICE'])


@dns_router.post('/record')
@inject
async def create_record(
    hostname: Annotated[str, Body()],
    ip: Annotated[str, Body()],
    record_type: Annotated[str, Body()],
    ttl: Annotated[str, Body()],
    dns_manager: FromDishka[DNSManager],
):
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
    dns_manager: FromDishka[DNSManager],
):
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
    ttl: Annotated[str, Body()],
    dns_manager: FromDishka[DNSManager],
):
    try:
        await dns_manager.update_record(hostname, ip, record_type, ttl)
    except Exception as e:
        raise HTTPException(500, f"{e}")


@dns_router.get('/record')
@inject
async def get_all_records(dns_manager: FromDishka[DNSManager]):
    try:
        return await dns_manager.get_all_records()
    except Exception as e:
        raise HTTPException(500, str(e))


@dns_router.post('/setup')
@inject
async def setup_dns(
        dns_ip_address: Annotated[str, Body()],
        dns_manager: FromDishka[DNSManager],
) -> None:
    await dns_manager.setup(dns_ip_address)
