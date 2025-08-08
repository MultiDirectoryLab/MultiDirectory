"""FastAPI adapter for MFAManager.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse

from api.auth.adapters.cookie_mixin import ResponseCookieMixin
from api.auth.schema import (
    MFAChallengeResponse,
    MFACreateRequest,
    MFAGetResponse,
    OAuth2Form,
)
from api.exceptions.mfa import (
    ForbiddenError,
    InvalidCredentialsError,
    MFAError,
    MFATokenError,
    MissingMFACredentialsError,
    NetworkPolicyError,
    NotFoundError,
)
from ldap_protocol.identity import MFAManager
from ldap_protocol.multifactor import MFA_HTTP_Creds, MFA_LDAP_Creds


class MFAFastAPIAdapter(ResponseCookieMixin):
    """Adapter for using MFAManager with FastAPI."""

    def __init__(self, mfa_manager: "MFAManager"):
        """Initialize the adapter with a domain MFAManager instance.

        :param mfa_manager: MFAManager instance (domain logic)
        """
        self._manager = mfa_manager

    async def setup_mfa(self, mfa: MFACreateRequest) -> bool:
        """Create or update MFA keys.

        :param mfa: MFACreateRequest
        :return: bool
        """
        return await self._manager.setup_mfa(mfa)

    async def remove_mfa(self, scope: str) -> None:
        """Delete MFA keys by scope.

        :param scope: str ('http' or 'ldap')
        :return: None
        """
        await self._manager.remove_mfa(scope)

    async def get_mfa(
        self,
        mfa_creds: MFA_HTTP_Creds,
        mfa_creds_ldap: MFA_LDAP_Creds,
    ) -> MFAGetResponse:
        """Get MFA keys for http and ldap.

        :param mfa_creds: MFA_HTTP_Creds
        :param mfa_creds_ldap: MFA_LDAP_Creds
        :return: MFAGetResponse
        """
        return await self._manager.get_mfa(mfa_creds, mfa_creds_ldap)

    async def callback_mfa(
        self,
        access_token: str,
        mfa_creds: MFA_HTTP_Creds,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
    ) -> RedirectResponse:
        """Process MFA callback and return redirect.

        :param access_token: str
        :param mfa_creds: MFA_HTTP_Creds
        :param ip: IP address
        :param user_agent: str
        :return: RedirectResponse
        :raises HTTPException: 404 if not found
        :raises HTTPException: 302 redirect if MFA token error
        """
        try:
            key = await self._manager.callback_mfa(
                access_token,
                mfa_creds,
                ip,
                user_agent,
            )
            response = RedirectResponse("/", 302)
            await self.set_session_cookie(
                response,
                self._manager.key_ttl,
                key,
            )
            return response
        except MFATokenError:
            return RedirectResponse("/mfa_token_error", status.HTTP_302_FOUND)

        except NotFoundError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from e

    async def two_factor_protocol(
        self,
        form: OAuth2Form,
        request: Request,
        ip: IPv4Address | IPv6Address,
    ) -> MFAChallengeResponse:
        """Initiate two-factor protocol with application.

        :param form: OAuth2Form
        :param request: FastAPI Request
        :param ip: IP address
        :return: MFAChallengeResponse
        :raises HTTPException: 422 if invalid credentials or not found
        :raises HTTPException: 403 if forbidden
            (missing API credentials, network policy violation, etc.)
        :raises HTTPException: 406 if MFA error
        """
        try:
            result = await self._manager.two_factor_protocol(
                form=form,
                url=request.url_for("callback_mfa"),
                ip=ip,
            )
            return result
        except InvalidCredentialsError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            )

        except (
            MissingMFACredentialsError,
            NetworkPolicyError,
            ForbiddenError,
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN)

        except NotFoundError:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY)

        except MFAError as exc:
            raise HTTPException(
                status.HTTP_406_NOT_ACCEPTABLE,
                detail=str(exc),
            )
