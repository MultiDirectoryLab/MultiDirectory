"""Shadow api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from ipaddress import IPv4Address
from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import APIRouter, Body, HTTPException, status
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.multifactor import LDAPMultiFactorAPI, MultifactorAPI
from ldap_protocol.policies.network_policy import get_user_network_policy
from models import MFAFlags, User

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
    query = select(User).filter(User.user_principal_name.ilike(principal))

    user = await session.scalar(query)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    network_policy = await get_user_network_policy(
        ip,
        user,
        session,
    )

    if network_policy is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    if not network_policy.is_kerberos:
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

        try:
            if await mfa.ldap_validate_mfa(user.user_principal_name, None):
                return True

        except MultifactorAPI.MFAConnectError:
            logger.error("MFA connect error")
            if network_policy.bypass_no_connection:
                return True
        except MultifactorAPI.MFAMissconfiguredError:
            logger.error("MFA missconfigured error")
            return True  # TODO: add network_policy.bypass_missconfigured
        except MultifactorAPI.MultifactorError:
            logger.error("MFA service failure")
            if network_policy.bypass_service_failure:
                return True

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
    )
