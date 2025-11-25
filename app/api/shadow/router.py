"""Shadow api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address
from typing import Annotated

from dishka import FromDishka
from fastapi import Body, status
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from api.error_routing import (
    ERROR_MAP_TYPE,
    DishkaErrorAwareRoute,
    DomainErrorTranslator,
)
from enums import DoaminCodes
from ldap_protocol.auth.exceptions.mfa import (
    AuthenticationError,
    InvalidCredentialsError,
    NetworkPolicyError,
)
from ldap_protocol.policies.password.exceptions import PasswordPolicyError

from ldap_protocol.rootdse.dto import DomainControllerInfo
from ldap_protocol.rootdse.reader import DCInfoReader

from .adapter import ShadowAdapter

translator = DomainErrorTranslator(DoaminCodes.SHADOW)


error_map: ERROR_MAP_TYPE = {
    InvalidCredentialsError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    NetworkPolicyError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    AuthenticationError: rule(
        status=status.HTTP_401_UNAUTHORIZED,
        translator=translator,
    ),
    PasswordPolicyError: rule(
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        translator=translator,
    ),
    PermissionError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
}
shadow_router = ErrorAwareRouter(route_class=DishkaErrorAwareRoute)


@shadow_router.post("/mfa/push", error_map=error_map)
async def proxy_request(
    principal: Annotated[str, Body(embed=True)],
    ip: Annotated[IPv4Address, Body(embed=True)],
    adapter: FromDishka[ShadowAdapter],
) -> None:
    """Proxy request to mfa."""
    return await adapter.proxy_request(principal, ip)


@shadow_router.post("/sync/password", error_map=error_map)
async def change_password(
    principal: Annotated[str, Body(embed=True)],
    new_password: Annotated[str, Body(embed=True)],
    adapter: FromDishka[ShadowAdapter],
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
    return await adapter.change_password(principal, new_password)


@shadow_router.get("/metadata/dcinfo")
async def get_dcinfo(
    dcreader: FromDishka[DCInfoReader],
) -> DomainControllerInfo:
    return await dcreader.get()
