"""Shadow api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from ipaddress import IPv4Address
from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import APIRouter, Body, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.multifactor import LDAPMultiFactorAPI
from ldap_protocol.utils.queries import get_user_network_policy
from models import MFAFlags, PolicyProtocol, User

shadow_router = APIRouter()


@shadow_router.post("/get/push/principal")
@inject
async def proxy_request(
    principal: Annotated[str, Body(embed=True)],
    ip: Annotated[IPv4Address, Body(embed=True)],
    mfa: FromDishka[LDAPMultiFactorAPI],
    session: FromDishka[AsyncSession],
) -> bool:
    """Proxy request to mfa."""
    for _ in range(3):
        user = await session.scalar(
            select(User)
            .filter(User.sam_accout_name == principal),
        )

        if user:
            break

        principal = principal[:-1]
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    network_policy = await get_user_network_policy(
        ip,
        user,
        PolicyProtocol.Kerberos,
        session,
    )

    if network_policy is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    if not mfa:  # noqa: R505
        return True
    elif network_policy.mfa_status == MFAFlags.DISABLED:
        return True
    elif network_policy.mfa_status in (MFAFlags.ENABLED, MFAFlags.WHITELIST):
        if (
            network_policy.mfa_status == MFAFlags.WHITELIST
            and not network_policy.mfa_groups
        ):
            return True

        return await mfa.ldap_validate_mfa(user.user_principal_name, None)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
    )
