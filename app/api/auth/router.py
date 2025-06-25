"""Auth api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Body, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.utils import get_ip_from_request, get_user_agent_from_request
from api.utils import AuthManager
from api.utils.exceptions import (
    ForbiddenError,
    KerberosError,
    MFAError,
    UnauthorizedError,
)
from config import Settings
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.multifactor import MultifactorAPI
from ldap_protocol.session_storage import SessionStorage

from .oauth2 import get_current_user
from .schema import OAuth2Form, SetupRequest

auth_router = APIRouter(prefix="/auth", tags=["Auth"], route_class=DishkaRoute)


@auth_router.post("/")
async def login(
    form: Annotated[OAuth2Form, Depends()],
    session: FromDishka[AsyncSession],
    settings: FromDishka[Settings],
    mfa: FromDishka[MultifactorAPI],
    storage: FromDishka[SessionStorage],
    response: Response,
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
    user_agent: Annotated[str, Depends(get_user_agent_from_request)],
    auth_manager: FromDishka[AuthManager],
) -> None:
    """Create session to cookies and storage.

    - **username**: username formats:
    `DN`, `userPrincipalName`, `saMAccountName`
    - **password**: password

    \f
    :param Annotated[OAuth2Form, Depends form: login form
    :param FromDishka[AsyncSession] session: db
    :param FromDishka[Settings] settings: app settings
    :param FromDishka[MultifactorAPI] mfa: mfa api wrapper
    :param FromDishka[SessionStorage] storage: session storage
    :param Response response: FastAPI response
    :param Annotated[IPv4Address  |  IPv6Address, Depends ip: client ip
    :param Annotated[str, Depends user_agent: client user agent
    :param FromDishka[AuthManager] auth_manager: auth manager
    :raises HTTPException: 401 if incorrect username or password
    :raises HTTPException: 403 if user not part of domain admins
    :raises HTTPException: 403 if user account is disabled
    :raises HTTPException: 403 if user account is expired
    :raises HTTPException: 403 if ip is not provided
    :raises HTTPException: 403 if user not part of network policy
    :raises HTTPException: 426 if mfa required
    :return None: None
    """
    try:
        await auth_manager.login(
            form=form,
            response=response,
            ip=ip,
            user_agent=user_agent,
        )
    except UnauthorizedError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except ForbiddenError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except MFAError as exc:
        raise HTTPException(status.HTTP_426_UPGRADE_REQUIRED, detail=str(exc))


@auth_router.get("/me")
async def users_me(
    user: Annotated[UserSchema, Depends(get_current_user)],
) -> UserSchema:
    """Get current logged-in user data.

    :param user: UserSchema (current user)
    :return: UserSchema
    """
    return user


@auth_router.delete("/", response_class=Response)
async def logout(
    response: Response,
    storage: FromDishka[SessionStorage],
    user: Annotated[UserSchema, Depends(get_current_user)],
) -> None:
    """Delete token cookies and user session.

    :param response: FastAPI Response
    :param storage: SessionStorage
    :param user: UserSchema (current user)
    :return: None
    """
    response.delete_cookie("id", httponly=True)
    await storage.delete_user_session(user.session_id)


@auth_router.patch(
    "/user/password",
    status_code=200,
    dependencies=[Depends(get_current_user)],
)
async def password_reset(
    identity: Annotated[str, Body(examples=["admin"])],
    new_password: Annotated[str, Body(examples=["password"])],
    kadmin: FromDishka[AbstractKadmin],
    auth_manager: FromDishka[AuthManager],
) -> None:
    """Reset user's (entry) password.

    :param identity: user identity (userPrincipalName, saMAccountName or DN)
    :param new_password: new password
    :param kadmin: kadmin api
    :param auth_manager: AuthManager
    :raises HTTPException: 404 if user not found
    :raises HTTPException: 422 if password is invalid
    :raises HTTPException: 424 if kerberos password update failed
    :return: None
    """
    try:
        await auth_manager.reset_password(identity, new_password, kadmin)
    except KerberosError as exc:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, detail=str(exc))
    except ForbiddenError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )


@auth_router.get("/setup")
async def check_setup(auth_manager: FromDishka[AuthManager]) -> bool:
    """Check if initial setup is required.

    :param auth_manager: AuthManager
    :return: bool
    """
    return await auth_manager.check_setup_needed()


@auth_router.post(
    "/setup",
    status_code=status.HTTP_200_OK,
    responses={423: {"detail": "Locked"}},
)
async def first_setup(
    request: SetupRequest,
    auth_manager: FromDishka[AuthManager],
) -> None:
    """Perform initial structure and policy setup.

    :param request: SetupRequest
    :param auth_manager: AuthManager
    :raises HTTPException: 423 if setup already performed
    :return: None
    """
    try:
        await auth_manager.perform_first_setup(request)
    except ForbiddenError as exc:
        raise HTTPException(status.HTTP_423_LOCKED, detail=str(exc))
