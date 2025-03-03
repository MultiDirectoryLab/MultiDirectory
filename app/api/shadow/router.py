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

from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.multifactor import LDAPMultiFactorAPI, MultifactorAPI
from ldap_protocol.policies.network_policy import get_user_network_policy
from ldap_protocol.policies.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from models import MFAFlags, User
from security import get_password_hash

shadow_router = APIRouter()


@shadow_router.post("/mfa/push")
@inject
async def proxy_request(
    principal: Annotated[str, Body(embed=True)],
    ip: Annotated[IPv4Address, Body(embed=True)],
    mfa: FromDishka[LDAPMultiFactorAPI],
    session: FromDishka[AsyncSession],
) -> None:
    """Proxy request to mfa."""
    query = select(User).filter(User.user_principal_name.ilike(principal))

    user = await session.scalar(query)

    if not user:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

    network_policy = await get_user_network_policy(
        ip,
        user,
        session,
    )

    if network_policy is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    if not network_policy.is_kerberos:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    if not mfa or network_policy.mfa_status == MFAFlags.DISABLED:
        return
    elif network_policy.mfa_status in (MFAFlags.ENABLED, MFAFlags.WHITELIST):
        if (
            network_policy.mfa_status == MFAFlags.WHITELIST
            and not network_policy.mfa_groups
        ):
            return

        try:
            if await mfa.ldap_validate_mfa(user.user_principal_name, None):
                return

        except MultifactorAPI.MFAConnectError:
            logger.error("MFA connect error")
            if network_policy.bypass_no_connection:
                return
        except MultifactorAPI.MFAMissconfiguredError:
            logger.error("MFA missconfigured error")
            return  # TODO: add network_policy.bypass_missconfigured
        except MultifactorAPI.MultifactorError:
            logger.error("MFA service failure")
            if network_policy.bypass_service_failure:
                return

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


@shadow_router.post("/sync/password")
@inject
async def sync_password(
    principal: Annotated[str, Body(embed=True)],
    new_password: Annotated[str, Body(embed=True)],
    session: FromDishka[AsyncSession],
    kadmin: FromDishka[AbstractKadmin],
) -> None:
    """Reset user's (entry) password.

    - **principal**: user upn
    - **new_password**: password to set
    \f
    :param FromDishka[AsyncSession] session: db
    :param FromDishka[AbstractKadmin] kadmin: kadmin api
    :param Annotated[str, Body principal: reset target user
    :param Annotated[str, Body new_password: new password for user
    :raises HTTPException: 404 if user not found
    :raises HTTPException: 422 if password not valid
    :return None: None
    """
    query = select(User).filter(User.user_principal_name.ilike(principal))

    user = await session.scalar(query)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    policy = await PasswordPolicySchema.get_policy_settings(session, kadmin)
    errors = await policy.validate_password_with_policy(new_password, user)

    if errors:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=errors,
        )

    user.password = get_password_hash(new_password)
    await post_save_password_actions(user, session)
