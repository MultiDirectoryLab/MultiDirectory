"""Shadow api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from typing import Annotated

from dishka import FromDishka
from fastapi import APIRouter, Body
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.multifactor import MultifactorAPI

shadow_router = APIRouter()


@shadow_router.post("/get/push/principal")
async def proxy_request(
    principal: Annotated[str, Body(embed=True)],
    mfa: FromDishka[MultifactorAPI],
    session: FromDishka[AsyncSession],
) -> bool:
    """Proxy request to mfa."""
    return await mfa.ldap_validate_mfa(principal, None) if mfa else False
