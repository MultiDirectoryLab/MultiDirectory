"""Shadow api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address
from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Body, HTTPException, status
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.multifactor import LDAPMultiFactorAPI, MultifactorAPI
from ldap_protocol.policies.network_policy import get_user_network_policy
from ldap_protocol.policies.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from ldap_protocol.utils.queries import get_user
from models import MFAFlags
from security import get_password_hash

shadow_router = APIRouter(route_class=DishkaRoute)


@shadow_router.post("/mfa/push")
async def proxy_request(
    principal: Annotated[str, Body(embed=True)],
    ip: Annotated[IPv4Address, Body(embed=True)],
    mfa: FromDishka[LDAPMultiFactorAPI],
    session: FromDishka[AsyncSession],
) -> None:
    """Proxy request to mfa.

    Args:
        principal (str): user principal name
        ip (IPv4Address): user ip address
        mfa (FromDishka[LDAPMultiFactorAPI]): mfa api
        session (FromDishka[AsyncSession]): db session

    Raises:
        HTTPException: 401 if mfa is required but not passed or failed
        HTTPException: 403 if user is not allowed to use kerberos
        HTTPException: 422 if user not found
    """
    user = await get_user(session, principal)

    if not user:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)

    network_policy = await get_user_network_policy(
        ip,
        user,
        session,
    )

    if network_policy is None or not network_policy.is_kerberos:
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
            return
        except MultifactorAPI.MultifactorError:
            logger.error("MFA service failure")
            if network_policy.bypass_service_failure:
                return

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


@shadow_router.post("/sync/password")
async def sync_password(
    principal: Annotated[str, Body(embed=True)],
    new_password: Annotated[str, Body(embed=True)],
    session: FromDishka[AsyncSession],
) -> None:
    """Reset user's (entry) password.

    - **principal**: user upn
    - **new_password**: password to set
    \f
    Args:
        principal Annotated[str, Body]: reset target user
        new_password Annotated[str, Body]: new password for user
        session (FromDishka[AsyncSession]): db

    Raises:
        HTTPException: 404 if user not found
        HTTPException: 422 if password not valid
    """
    user = await get_user(session, principal)

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    policy = await PasswordPolicySchema.get_policy_settings(session)
    errors = await policy.validate_password_with_policy(new_password, user)

    if errors:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=errors,
        )

    user.password = get_password_hash(new_password)
    await post_save_password_actions(user, session)
