"""Shadow api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import APIRouter, Body
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.multifactor import MultifactorAPI
from models import Directory

shadow_router = APIRouter()


@shadow_router.post("/get/push/principal")
@inject
async def proxy_request(
    principal: Annotated[str, Body(embed=True)],
    mfa: FromDishka[MultifactorAPI],
    session: FromDishka[AsyncSession],
) -> bool:
    """Proxy request to mfa."""
    if not mfa:
        return False

    for _ in range(3):
        if await session.scalar(
            select(Directory)
            .filter(Directory.name == principal),
        ):
            break

        principal = principal[:-1]
    else:
        return False

    return await mfa.ldap_validate_mfa(principal, None)
