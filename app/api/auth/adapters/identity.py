"""FastAPI adapter for IdentityManager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from fastapi import Request, Response, status

from api.auth.adapters.cookie_mixin import ResponseCookieMixin
from api.base_adapter import BaseAdapter
from api.exceptions.auth import (
    AlreadyConfiguredError,
    LoginFailedError,
    PasswordPolicyError,
    UnauthorizedError,
    UserNotFoundError,
)
from api.exceptions.mfa import (
    MFAError,
    MFARequiredError,
    MissingMFACredentialsError,
)
from ldap_protocol.identity import IdentityManager
from ldap_protocol.identity.schemas import (
    MFAChallengeResponse,
    OAuth2Form,
    SetupRequest,
)
from ldap_protocol.kerberos import KRBAPIError


class IdentityFastAPIAdapter(
    ResponseCookieMixin,
    BaseAdapter[IdentityManager],
):
    """Adapter for using IdentityManager with FastAPI."""

    _exceptions_map: dict[type[Exception], int] = {
        UnauthorizedError: status.HTTP_401_UNAUTHORIZED,
        LoginFailedError: status.HTTP_403_FORBIDDEN,
        MFARequiredError: status.HTTP_426_UPGRADE_REQUIRED,
        PasswordPolicyError: status.HTTP_422_UNPROCESSABLE_ENTITY,
        UserNotFoundError: status.HTTP_404_NOT_FOUND,
        KRBAPIError: status.HTTP_424_FAILED_DEPENDENCY,
        AlreadyConfiguredError: status.HTTP_423_LOCKED,
        MissingMFACredentialsError: status.HTTP_403_FORBIDDEN,
        MFAError: status.HTTP_406_NOT_ACCEPTABLE,
    }

    async def login(
        self,
        form: OAuth2Form,
        request: Request,
        response: Response,
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
        mfa_challenge, key = await self._service.login(
            form=form,
            url=request.url_for("callback_mfa"),
            ip=ip,
            user_agent=user_agent,
        )
        if key is not None:
            await self.set_session_cookie(
                response,
                self._service.key_ttl,
                key,
            )
        return mfa_challenge

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
        await self._service.perform_first_setup(request)
