"""FastAPI adapter for IdentityManager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from fastapi import HTTPException, Response, status

from api.auth.adapters.cookie_mixin import ResponseCookieMixin
from api.auth.schema import OAuth2Form, SetupRequest
from api.exceptions.auth import (
    AlreadyConfiguredError,
    LoginFailedError,
    PasswordPolicyError,
    UnauthorizedError,
    UserLockedError,
    UserNotFoundError,
)
from api.exceptions.mfa import MFARequiredError
from ldap_protocol.identity import IdentityManager
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError


class IdentityFastAPIAdapter(ResponseCookieMixin):
    """Adapter for using IdentityManager with FastAPI."""

    def __init__(self, identity_manager: "IdentityManager"):
        """Initialize the adapter with a domain IdentityManager instance.

        :param identity_manager: IdentityManager instance (domain logic)
        """
        self._manager = identity_manager

    async def login(
        self,
        form: OAuth2Form,
        response: Response,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
    ) -> None:
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
        try:
            key = await self._manager.login(
                form=form,
                ip=ip,
                user_agent=user_agent,
            )
            await self.set_session_cookie(
                response,
                self._manager.key_ttl,
                key,
            )
        except UserLockedError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is locked",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except UnauthorizedError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            )

        except LoginFailedError:
            raise HTTPException(status.HTTP_403_FORBIDDEN)

        except MFARequiredError as exc:
            raise HTTPException(
                status.HTTP_426_UPGRADE_REQUIRED,
                detail=str(exc),
            )

    async def reset_password(
        self,
        identity: str,
        new_password: str,
        kadmin: AbstractKadmin,
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
        try:
            await self._manager.reset_password(identity, new_password, kadmin)
        except PasswordPolicyError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=exc.args[0],
            )

        except UserNotFoundError:
            raise HTTPException(status.HTTP_404_NOT_FOUND)

        except KRBAPIError as exc:
            raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, str(exc))

    async def check_setup_needed(self) -> bool:
        """Check if initial setup is required.

        :return: True if setup is required, False otherwise
        """
        return await self._manager.check_setup_needed()

    async def perform_first_setup(self, request: SetupRequest) -> None:
        """Perform initial structure and policy setup.

        :param request: SetupRequest with setup parameters
        :raises HTTPException: 423 if setup already performed
        :return: None
        """
        try:
            await self._manager.perform_first_setup(request)
        except AlreadyConfiguredError as exc:
            raise HTTPException(status.HTTP_423_LOCKED, detail=str(exc))
