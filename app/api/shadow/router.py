"""Shadow api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address
from typing import Annotated

from dishka import FromDishka
from fastapi import Body
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from enums import ProjectPartCodes
from errors import (
    ERROR_MAP_TYPE,
    BaseErrorTranslator,
    DishkaErrorAwareRoute,
    ErrorStatusCodes,
)
from ldap_protocol.identity.exceptions import (
    AuthenticationError,
    InvalidCredentialsError,
    NetworkPolicyError,
)
from ldap_protocol.policies.password.exceptions import PasswordPolicyError

from .adapter import ShadowAdapter


class ShadowErrorTranslator(BaseErrorTranslator):
    """Shadow error translator."""

    domain_code = ProjectPartCodes.SHADOW


error_map: ERROR_MAP_TYPE = {
    InvalidCredentialsError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=ShadowErrorTranslator(),
    ),
    NetworkPolicyError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=ShadowErrorTranslator(),
    ),
    AuthenticationError: rule(
        status=ErrorStatusCodes.UNAUTHORIZED,
        translator=ShadowErrorTranslator(),
    ),
    PasswordPolicyError: rule(
        status=ErrorStatusCodes.UNPROCESSABLE_ENTITY,
        translator=ShadowErrorTranslator(),
    ),
    PermissionError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=ShadowErrorTranslator(),
    ),
}
shadow_router = ErrorAwareRouter(
    prefix="/shadow",
    tags=["Shadow"],
    route_class=DishkaErrorAwareRoute,
)


@shadow_router.post("/mfa/push")
async def proxy_request(
    principal: Annotated[str, Body(embed=True)],
    ip: Annotated[IPv4Address, Body(embed=True)],
    adapter: FromDishka[ShadowAdapter],
) -> None:
    """Proxy request to mfa."""
    return await adapter.proxy_request(principal, ip)


@shadow_router.post("/sync/password")
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
