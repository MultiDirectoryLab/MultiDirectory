"""Network policies.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.routing import APIRouter

from api.auth import get_current_user
from api.auth.utils import get_ip_from_request, get_user_agent_from_request
from api.utils import MFAManagerFastAPIAdapter
from ldap_protocol.multifactor import MFA_HTTP_Creds, MFA_LDAP_Creds

from .schema import (
    MFAChallengeResponse,
    MFACreateRequest,
    MFAGetResponse,
    OAuth2Form,
)

mfa_router = APIRouter(
    prefix="/multifactor",
    tags=["Multifactor"],
    route_class=DishkaRoute,
)


@mfa_router.post(
    "/setup",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_user)],
)
async def setup_mfa(
    mfa: MFACreateRequest,
    mfa_manager: FromDishka[MFAManagerFastAPIAdapter],
) -> bool:
    """Set mfa credentials, rewrites if exists.

    \f
    :param MFACreateRequest mfa: MuliFactor credentials
    :param FromDishka[MFAManagerFastAPIAdapter] mfa_manager: mfa manager
    :return bool: status
    """
    return await mfa_manager.setup_mfa(mfa)


@mfa_router.delete(
    "/keys",
    dependencies=[Depends(get_current_user)],
)
async def remove_mfa(
    scope: Literal["ldap", "http"],
    mfa_manager: FromDishka[MFAManagerFastAPIAdapter],
) -> None:
    """Remove mfa credentials."""
    await mfa_manager.remove_mfa(scope)


@mfa_router.post("/get", dependencies=[Depends(get_current_user)])
async def get_mfa(
    mfa_creds: FromDishka[MFA_HTTP_Creds],
    mfa_creds_ldap: FromDishka[MFA_LDAP_Creds],
    mfa_manager: FromDishka[MFAManagerFastAPIAdapter],
) -> MFAGetResponse:
    """Get MFA creds.

    \f
    :return MFAGetResponse: response.
    """
    return await mfa_manager.get_mfa(mfa_creds, mfa_creds_ldap)


@mfa_router.post("/create", name="callback_mfa", include_in_schema=True)
async def callback_mfa(
    access_token: Annotated[
        str,
        Form(alias="accessToken", validation_alias="accessToken"),
    ],
    mfa_creds: FromDishka[MFA_HTTP_Creds],
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
    user_agent: Annotated[str, Depends(get_user_agent_from_request)],
    mfa_manager: FromDishka[MFAManagerFastAPIAdapter],
) -> RedirectResponse:
    """Disassemble mfa token and send redirect.

    Callback endpoint for MFA.
    \f
    :param FromDishka[MFA_HTTP_Creds] mfa_creds:
        creds for multifactor (http app)
    :param Annotated[IPv4Address  |  IPv6Address, Depends ip: client ip
    :param Annotated[str, Form access_token: token from multifactor callback
    :raises HTTPException: if mfa not set up
    :return RedirectResponse: on bypass or success
    """
    return await mfa_manager.callback_mfa(
        access_token,
        mfa_creds,
        ip,
        user_agent,
    )


@mfa_router.post("/connect", response_model=MFAChallengeResponse)
async def two_factor_protocol(
    form: Annotated[OAuth2Form, Depends()],
    request: Request,
    response: Response,
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
    user_agent: Annotated[str, Depends(get_user_agent_from_request)],
    mfa_manager: FromDishka[MFAManagerFastAPIAdapter],
) -> MFAChallengeResponse:
    """Initiate two factor protocol with app.

    \f
    :param Annotated[OAuth2Form, Depends form: password form
    :param Request request: FastAPI request
    :param FromDishka[MultifactorAPI] api: wrapper for MFA DAO
    :param Response response: FastAPI response
    :param Annotated[IPv4Address  |  IPv6Address, Depends ip: client ip
    :raises HTTPException: Missing API credentials
    :raises HTTPException: Invalid credentials
    :raises HTTPException: network policy violation
    :raises HTTPException: Multifactor error
    :return MFAChallengeResponse:
        {'status': 'pending', 'message': https://example.com}.
    """
    return await mfa_manager.two_factor_protocol(
        form,
        request,
        response,
        ip,
        user_agent,
    )
