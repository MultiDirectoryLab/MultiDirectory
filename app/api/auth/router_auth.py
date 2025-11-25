"""Auth api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from dishka import FromDishka
from fastapi import Body, Depends, Request, Response, status
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from api.auth.adapters import AuthFastAPIAdapter
from api.auth.utils import get_ip_from_request, get_user_agent_from_request
from api.error_routing import (
    ERROR_MAP_TYPE,
    DishkaErrorAwareRoute,
    DomainErrorTranslator,
)
from enums import DoaminCodes
from ldap_protocol.auth.exceptions.mfa import (
    MFAAPIError,
    MFAConnectError,
    MFARequiredError,
    MissingMFACredentialsError,
)
from ldap_protocol.auth.schemas import (
    MFAChallengeResponse,
    OAuth2Form,
    SetupRequest,
)
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.identity.exceptions import (
    IdentityAlreadyConfiguredError,
    IdentityForbiddenError,
    IdentityLoginFailedError,
    IdentityPasswordPolicyError,
    IdentityUnauthorizedError,
    IdentityUserNotFoundError,
    IdentityValidationError,
)
from ldap_protocol.kerberos.exceptions import KRBAPIChangePasswordError
from ldap_protocol.session_storage import SessionStorage

from .utils import verify_auth

translator = DomainErrorTranslator(DoaminCodes.AUTH)


error_map: ERROR_MAP_TYPE = {
    IdentityUnauthorizedError: rule(
        status=status.HTTP_401_UNAUTHORIZED,
        translator=translator,
    ),
    IdentityAlreadyConfiguredError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    IdentityForbiddenError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    IdentityLoginFailedError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    IdentityPasswordPolicyError: rule(
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        translator=translator,
    ),
    IdentityUserNotFoundError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    IdentityValidationError: rule(
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        translator=translator,
    ),
    MFARequiredError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    MissingMFACredentialsError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    MFAAPIError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    MFAConnectError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    PermissionError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
    KRBAPIChangePasswordError: rule(
        status=status.HTTP_400_BAD_REQUEST,
        translator=translator,
    ),
}


auth_router = ErrorAwareRouter(
    prefix="/auth",
    tags=["Auth"],
    route_class=DishkaErrorAwareRoute,
)


@auth_router.post("/", error_map=error_map)
async def login(
    form: Annotated[OAuth2Form, Depends()],
    request: Request,
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
    user_agent: Annotated[str, Depends(get_user_agent_from_request)],
    auth_manager: FromDishka[AuthFastAPIAdapter],
) -> MFAChallengeResponse | None:
    """Create session to cookies and storage.

    - **username**: username formats:
    `DN`, `userPrincipalName`, `saMAccountName`
    - **password**: password

    \f
    :param Annotated[OAuth2Form, Depends form: login form
    :param Response response: FastAPI response
    :param Annotated[IPv4Address  |  IPv6Address, Depends ip: client ip
    :param Annotated[str, Depends user_agent: client user agent
    :param FromDishka[IdentityFastAPIAdapter] auth_manager: auth manager
    :raises HTTPException: 401 if incorrect username or password
    :raises HTTPException: 403 if user not part of domain admins
    :raises HTTPException: 403 if user account is disabled
    :raises HTTPException: 403 if user account is expired
    :raises HTTPException: 403 if ip is not provided
    :raises HTTPException: 403 if user not part of network policy
    :return None: None
    """
    return await auth_manager.login(
        form=form,
        request=request,
        ip=ip,
        user_agent=user_agent,
    )


@auth_router.get("/me", error_map=error_map)
async def users_me(
    identity_adapter: FromDishka[AuthFastAPIAdapter],
) -> UserSchema:
    """Get current logged-in user data.

    :param identity_adapter: IdentityFastAPIAdapter instance for user
        identity operations
    :return: UserSchema
    """
    return await identity_adapter.get_current_user()


@auth_router.delete(
    "/",
    response_class=Response,
    error_map=error_map,
)
async def logout(
    response: Response,
    storage: FromDishka[SessionStorage],
    identity_adapter: FromDishka[AuthFastAPIAdapter],
) -> None:
    """Delete token cookies and user session.

    :param response: FastAPI Response
    :param storage: SessionStorage
    :param user: UserSchema (current user)
    :return: None
    """
    user = await identity_adapter.get_current_user()
    response.delete_cookie("id", httponly=True)
    await storage.delete_user_session(user.session_id)


@auth_router.patch(
    "/user/password",
    status_code=200,
    dependencies=[Depends(verify_auth)],
    error_map=error_map,
)
async def password_reset(
    auth_manager: FromDishka[AuthFastAPIAdapter],
    identity: Annotated[str, Body(examples=["admin"])],
    new_password: Annotated[str, Body(examples=["password"])],
    old_password: Annotated[
        str | None,
        Body(examples=["old_password"]),
    ] = None,
) -> None:
    """Reset user's (entry) password.

    :param identity: user identity (userPrincipalName, saMAccountName or DN)
    :param new_password: new password
    :param old_password: old password (if verifying)
    :param auth_manager: IdentityFastAPIAdapter
    :raises HTTPException: 404 if user not found
    :raises HTTPException: 422 if password is invalid
    :raises HTTPException: 424 if kerberos password update failed
    :return: None
    """
    await auth_manager.reset_password(identity, new_password, old_password)


@auth_router.get("/setup", error_map=error_map)
async def check_setup(
    auth_manager: FromDishka[AuthFastAPIAdapter],
) -> bool:
    """Check if initial setup is required.

    :param auth_manager: IdentityFastAPIAdapter
    :return: bool
    """
    return await auth_manager.check_setup_needed()


@auth_router.post(
    "/setup",
    status_code=status.HTTP_200_OK,
    responses={423: {"detail": "Locked"}},
    error_map=error_map,
)
async def first_setup(
    request: SetupRequest,
    auth_manager: FromDishka[AuthFastAPIAdapter],
) -> None:
    """Perform initial structure and policy setup.

    :param request: SetupRequest
    :param auth_manager: IdentityFastAPIAdapter
    :raises HTTPException: 423 if setup already performed
    :return: None
    """
    await auth_manager.perform_first_setup(request)
