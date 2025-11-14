"""FastAPI adapter for IdentityManager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from adaptix.conversion import get_converter
from fastapi import Request, status

from api.base_adapter import BaseAdapter
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.identity import IdentityManager
from ldap_protocol.identity.dto import SetupDTO
from ldap_protocol.identity.exceptions.auth import (
    AlreadyConfiguredError,
    LoginFailedError,
    PasswordPolicyError,
    UnauthorizedError,
    UserNotFoundError,
)
from ldap_protocol.identity.exceptions.mfa import (
    MFAAPIError,
    MFAConnectError,
    MFARequiredError,
    MissingMFACredentialsError,
)
from ldap_protocol.identity.schemas import (
    MFAChallengeResponse,
    OAuth2Form,
    SetupRequest,
)
from ldap_protocol.kerberos.exceptions import KRBAPIChangePasswordError

_convert_request_to_dto = get_converter(SetupRequest, SetupDTO)


class IdentityFastAPIAdapter(BaseAdapter[IdentityManager]):
    """Adapter for using IdentityManager with FastAPI."""

    _exceptions_map: dict[type[Exception], int] = {
        UnauthorizedError: status.HTTP_401_UNAUTHORIZED,
        LoginFailedError: status.HTTP_403_FORBIDDEN,
        MFARequiredError: status.HTTP_426_UPGRADE_REQUIRED,
        PasswordPolicyError: status.HTTP_422_UNPROCESSABLE_ENTITY,
        PermissionError: status.HTTP_403_FORBIDDEN,
        UserNotFoundError: status.HTTP_404_NOT_FOUND,
        KRBAPIChangePasswordError: status.HTTP_424_FAILED_DEPENDENCY,
        AlreadyConfiguredError: status.HTTP_423_LOCKED,
        MissingMFACredentialsError: status.HTTP_403_FORBIDDEN,
        MFAAPIError: status.HTTP_406_NOT_ACCEPTABLE,
        MFAConnectError: status.HTTP_406_NOT_ACCEPTABLE,
    }

    async def login(
        self,
        form: OAuth2Form,
        request: Request,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
    ) -> MFAChallengeResponse | None:
        """Log in a user and set session cookies.

        :param form: OAuth2Form with username and password
        :param response: FastAPI response (for setting cookies)
        :param ip: Client IP address
        :param user_agent: Client User-Agent string
        :raises HTTPException: 401 if incorrect username or password
        :raises HTTPException: 403 if access is forbidden
            (e.g. not in admins, disabled, expired, or policy failed)
        :raises HTTPException: 426 if MFA is required
        :return: None
        """
        login_dto = await self._service.login(
            form=form,
            url=request.url_for("callback_mfa"),
            ip=ip,
            user_agent=user_agent,
        )
        if login_dto.session_key is not None:
            self._service.set_new_session_key(
                login_dto.session_key,
            )
        return login_dto.mfa_challenge

    async def reset_password(
        self,
        identity: str,
        new_password: str,
    ) -> None:
        """Reset a user's password and update Kerberos principal.

        :param identity: User identity
            (userPrincipalName, sAMAccountName, or DN)
        :param new_password: New password string
        :param kadmin: Kerberos kadmin client
        :raises HTTPException: 404 if user not found
        :raises HTTPException: 422 if password is invalid
        :raises HTTPException: 424 if Kerberos password update failed
        :return: None
        """
        await self._service.reset_password(identity, new_password)

    async def check_setup_needed(self) -> bool:
        """Check if initial setup is required.

        :return: True if setup is required, False otherwise
        """
        return await self._service.check_setup_needed()

    async def perform_first_setup(self, request: SetupRequest) -> None:
        """Perform initial structure and policy setup.

        :param request: SetupRequest with setup parameters
        :raises HTTPException: 423 if setup already performed
        :return: None
        """
        await self._service.perform_first_setup(
            _convert_request_to_dto(request),
        )

    async def get_current_user(self) -> UserSchema:
        """Load the authenticated user using request-bound session data."""
        return await self._service.get_current_user()
