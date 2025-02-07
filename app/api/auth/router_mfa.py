"""Network policies.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import operator
import traceback
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi import Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.routing import APIRouter
from jose import JWTError, jwt
from jose.exceptions import JWKError
from loguru import logger
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from api.auth.utils import create_and_set_session_key, get_ip_from_request
from config import Settings
from ldap_protocol.multifactor import (
    Creds,
    MFA_HTTP_Creds,
    MFA_LDAP_Creds,
    MultifactorAPI,
)
from ldap_protocol.policies.network_policy import get_user_network_policy
from ldap_protocol.session_storage import SessionStorage
from models import CatalogueSetting
from models import User as DBUser

from .oauth2 import ALGORITHM, authenticate_user
from .schema import (
    MFAChallengeResponse,
    MFACreateRequest,
    MFAGetResponse,
    OAuth2Form,
)

mfa_router = APIRouter(prefix="/multifactor", tags=["Multifactor"])


@mfa_router.post(
    "/setup",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_user)],
)
@inject
async def setup_mfa(
    mfa: MFACreateRequest,
    session: FromDishka[AsyncSession],
) -> bool:
    """Set mfa credentials, rewrites if exists.
    \f
    :param str mfa_key: multifactor key
    :param Annotated[bool, Body is_ldap_scope: _description_, defaults to True
    :param str mfa_secret: multifactor api secret
    :return bool: status
    """  # noqa: D301
    async with session.begin_nested():
        await session.execute(
            (
                delete(CatalogueSetting).filter(
                    operator.or_(
                        CatalogueSetting.name == mfa.key_name,
                        CatalogueSetting.name == mfa.secret_name,
                    ),
                )
            ),
        )
        await session.flush()
        session.add(CatalogueSetting(name=mfa.key_name, value=mfa.mfa_key))
        session.add(
            CatalogueSetting(name=mfa.secret_name, value=mfa.mfa_secret),
        )
        await session.commit()

    return True


@mfa_router.delete("/keys", dependencies=[Depends(get_current_user)])
@inject
async def remove_mfa(
    session: FromDishka[AsyncSession],
    scope: Literal["ldap", "http"],
) -> None:
    """Remove mfa credentials."""
    if scope == 'http':
        keys = ["mfa_key", "mfa_secret"]
    else:
        keys = ["mfa_key_ldap", "mfa_secret_ldap"]

    await session.execute(
        delete(CatalogueSetting)
        .filter(CatalogueSetting.name.in_(keys)),
    )
    await session.commit()


@mfa_router.post("/get", dependencies=[Depends(get_current_user)])
@inject
async def get_mfa(
    mfa_creds: FromDishka[MFA_HTTP_Creds],
    mfa_creds_ldap: FromDishka[MFA_LDAP_Creds],
) -> MFAGetResponse:
    """Get MFA creds.
    \f
    :return MFAGetResponse: response
    """  # noqa: D301
    if not mfa_creds:
        mfa_creds = MFA_HTTP_Creds(Creds(None, None))
    if not mfa_creds_ldap:
        mfa_creds_ldap = MFA_LDAP_Creds(Creds(None, None))

    return MFAGetResponse(
        mfa_key=mfa_creds.key,
        mfa_secret=mfa_creds.secret,
        mfa_key_ldap=mfa_creds_ldap.key,
        mfa_secret_ldap=mfa_creds_ldap.secret,
    )


@mfa_router.post("/create", name="callback_mfa", include_in_schema=True)
@inject
async def callback_mfa(
    access_token: Annotated[str, Form(
        alias="accessToken", validation_alias="accessToken")],
    session: FromDishka[AsyncSession],
    storage: FromDishka[SessionStorage],
    settings: FromDishka[Settings],
    mfa_creds: FromDishka[MFA_HTTP_Creds],
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
) -> RedirectResponse:
    """Disassemble mfa token and send it to websocket.

    Callback endpoint for MFA.
    \f
    :param Annotated[str, Form access_token: access token from multifactor
    :param str | None mfa_secret: multifactor secret from settings
    :raises HTTPException: 404
    :return dict: status
    """  # noqa: D301
    if not mfa_creds:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    try:
        payload = jwt.decode(
            access_token,
            mfa_creds.secret,
            audience=mfa_creds.key,
            algorithms=ALGORITHM,
        )
    except (JWTError, AttributeError, JWKError) as err:
        logger.error(f"Invalid MFA token: {err}")
        return RedirectResponse("/mfa_token_error", status.HTTP_302_FOUND)

    user_id: int = int(payload.get("uid"))
    user = await session.get(DBUser, user_id)
    if user_id is None or not user:
        return RedirectResponse("/mfa_token_error", status.HTTP_302_FOUND)

    response = RedirectResponse("/", status.HTTP_302_FOUND)
    await create_and_set_session_key(
        user, session, settings, response, storage, ip)
    return response


@mfa_router.post("/connect", response_model=MFAChallengeResponse)
@inject
async def two_factor_protocol(
    form: Annotated[OAuth2Form, Depends()],
    request: Request,
    session: FromDishka[AsyncSession],
    api: FromDishka[MultifactorAPI],
    settings: FromDishka[Settings],
    storage: FromDishka[SessionStorage],
    response: Response,
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
) -> MFAChallengeResponse:
    """Authenticate with two factor app.
    \f
    :param Annotated[OAuth2Form, Depends form: login form
    :param Request request: request
    :param Annotated[AsyncSession, Depends session: db session
    :param Annotated[MultifactorAPI, Depends api: mfa api
    :raises HTTPException: Missing API credentials
    :raises HTTPException: Invalid credentials
    :raises HTTPException: Multifactor error
    :return MFAChallengeResponse:
        {'status': 'pending', 'message': https://example.com}
    """  # noqa: D301
    if not api:
        raise HTTPException(
            status.HTTP_428_PRECONDITION_REQUIRED,
            "Missing API credentials",
        )

    user = await authenticate_user(session, form.username, form.password)

    if not user:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Invalid credentials",
        )

    network_policy = await get_user_network_policy(ip, user, session)
    if network_policy is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN)

    try:
        url = request.url_for("callback_mfa")
        if settings.USE_CORE_TLS:
            url = url.replace(scheme="https")

        redirect_url = await api.get_create_mfa(
            user.user_principal_name,
            url.components.geturl(),
            user.id,
        )
    except MultifactorAPI.MFAConnectError:
        if network_policy.bypass_no_connection:
            await create_and_set_session_key(
                user, session, settings, response, storage, ip)
            return MFAChallengeResponse(status="bypass", message="")

        logger.critical(f"API error {traceback.format_exc()}")
        raise HTTPException(
            status.HTTP_406_NOT_ACCEPTABLE,
            "Multifactor error",
        )

    except MultifactorAPI.MFAMissconfiguredError:
        await create_and_set_session_key(
            user, session, settings, response, storage, ip)
        return MFAChallengeResponse(status="bypass", message="")

    except MultifactorAPI.MultifactorError:
        if network_policy.bypass_service_failure:
            await create_and_set_session_key(
                user, session, settings, response, storage, ip)
            return MFAChallengeResponse(status="bypass", message="")

        logger.critical(f"API error {traceback.format_exc()}")
        raise HTTPException(
            status.HTTP_406_NOT_ACCEPTABLE,
            "Multifactor error",
        )

    return MFAChallengeResponse(status="pending", message=redirect_url)
