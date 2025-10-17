"""LDAP requests bind.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import contextlib
from typing import AsyncGenerator, ClassVar

import httpx
from pydantic import Field
from sqlalchemy.ext.asyncio import AsyncSession

from entities import NetworkPolicy, User
from enums import MFAFlags
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import KRBAPIError
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_requests.bind_methods import (
    AbstractLDAPAuth,
    LDAPBindErrors,
    SaslAuthentication,
    SaslGSSAPIAuthentication,
    SimpleAuthentication,
    get_bad_response,
    sasl_mechanism_map,
)
from ldap_protocol.ldap_requests.bind_methods.sasl_spnego import (
    SaslSPNEGOAuthentication,
)
from ldap_protocol.ldap_responses import BaseResponse, BindResponse
from ldap_protocol.multifactor import MultifactorAPI
from ldap_protocol.objects import ProtocolRequests
from ldap_protocol.policies.network_policy import (
    check_mfa_group,
    is_user_group_valid,
)
from ldap_protocol.user_account_control import (
    UserAccountControlFlag,
    get_check_uac,
)
from ldap_protocol.utils.queries import (
    check_kerberos_group,
    set_user_logon_attrs,
)

from .base import BaseRequest
from .contexts import LDAPBindRequestContext, LDAPUnbindRequestContext


class BindRequest(BaseRequest):
    """Bind request fields mapping."""

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.BIND

    version: int
    name: str
    authentication_choice: AbstractLDAPAuth = Field(
        ...,
        alias="AuthenticationChoice",
    )

    @classmethod
    def from_data(cls, data: list[ASN1Row]) -> "BindRequest":
        """Get bind from data dict."""
        auth = data[2].tag_id

        otpassword: str | None
        auth_choice: AbstractLDAPAuth

        if auth == SimpleAuthentication.METHOD_ID:
            payload: str = data[2].value

            password = payload[:-6]
            otpassword = payload.removeprefix(password)

            if not otpassword.isdecimal():
                otpassword = None
                password = payload

            auth_choice = SimpleAuthentication(
                password=password,
                otpassword=otpassword,
            )
        elif auth == SaslAuthentication.METHOD_ID:
            sasl_method = data[2].value[0].value
            auth_choice = sasl_mechanism_map[sasl_method].from_data(
                data[2].value,
            )
        else:
            raise ValueError("Auth version not supported")

        return cls(
            version=data[0].value,
            name=data[1].value,
            AuthenticationChoice=auth_choice,
        )

    @staticmethod
    async def is_user_group_valid(
        user: User,
        ldap_session: LDAPSession,
        session: AsyncSession,
    ) -> bool:
        """Test compability."""
        return await is_user_group_valid(user, ldap_session.policy, session)

    @staticmethod
    async def check_mfa(
        api: MultifactorAPI | None,
        identity: str,
        otp: str | None,
        policy: NetworkPolicy,
    ) -> bool:
        """Check mfa api.

        :param User user: db user
        :param LDAPSession ldap_session: ldap session
        :param AsyncSession session: db session
        :return bool: response
        """
        if api is None:
            return False

        try:
            return await api.ldap_validate_mfa(identity, otp)
        except MultifactorAPI.MFAConnectError:
            return bool(policy.bypass_no_connection)
        except MultifactorAPI.MFAMissconfiguredError:
            return True
        except MultifactorAPI.MultifactorError:
            return bool(policy.bypass_service_failure)

    async def handle(
        self,
        ctx: LDAPBindRequestContext,
    ) -> AsyncGenerator[BindResponse, None]:
        """Handle bind request, check user and password."""
        if not self.name and self.authentication_choice.is_anonymous():
            yield BindResponse(result_code=LDAPCodes.SUCCESS)
            return

        if (
            isinstance(self.authentication_choice, SaslGSSAPIAuthentication)
            and (
                response := await self.authentication_choice.step(
                    ctx.session,
                    ctx.ldap_session,
                    ctx.settings,
                )
            )
        ):  # fmt: skip
            yield response
            return

        user = await self.authentication_choice.get_user(
            ctx.session,
            self.name,
        )
        self.set_event_data(
            {
                "details": {
                    "auth_choice": self.authentication_choice.method_name,
                },
            },
        )
        if not user or not self.authentication_choice.is_valid(
            user,
            ctx.password_validator,
        ):
            yield get_bad_response(LDAPBindErrors.LOGON_FAILURE)
            return

        uac_check = await get_check_uac(ctx.session, user.directory_id)

        if uac_check(UserAccountControlFlag.ACCOUNTDISABLE):
            yield get_bad_response(LDAPBindErrors.ACCOUNT_DISABLED)
            return

        if not await self.is_user_group_valid(
            user,
            ctx.ldap_session,
            ctx.session,
        ):
            yield get_bad_response(LDAPBindErrors.LOGON_FAILURE)
            return

        pwd_last_set = (
            await ctx.pwd_policy_use_cases.get_or_create_pwd_last_set(
                user.directory_id,
            )
        )
        password_policy = (
            await ctx.pwd_policy_use_cases.get_resulting_password_policy(
                user.directory_id,
            )
        )
        is_pwd_expired = await ctx.pwd_policy_use_cases.check_expired_max_age(
            password_policy,
            user,
        )

        is_krb_user = await check_kerberos_group(user, ctx.session)

        required_pwd_change = (
            pwd_last_set == "0" or is_pwd_expired  # noqa: S105
        ) and not is_krb_user

        if user.is_expired():
            yield get_bad_response(LDAPBindErrors.ACCOUNT_EXPIRED)
            return

        if required_pwd_change:
            yield get_bad_response(LDAPBindErrors.PASSWORD_MUST_CHANGE)
            return

        if (
            (policy := getattr(ctx.ldap_session, "policy", None))
            and policy.mfa_status in (MFAFlags.ENABLED, MFAFlags.WHITELIST)
            and ctx.mfa is not None
        ):
            request_2fa = True
            if policy.mfa_status == MFAFlags.WHITELIST:
                request_2fa = await check_mfa_group(policy, user, ctx.session)

            if request_2fa:
                mfa_status = await self.check_mfa(
                    ctx.mfa,
                    user.user_principal_name,
                    self.authentication_choice.otpassword,
                    policy,
                )

                if mfa_status is False:
                    yield get_bad_response(LDAPBindErrors.LOGON_FAILURE)
                    return

        with contextlib.suppress(KRBAPIError, httpx.TimeoutException):
            await ctx.kadmin.add_principal(
                user.get_upn_prefix(),
                self.authentication_choice.password.get_secret_value(),
                0.1,
            )

        await ctx.ldap_session.set_user(user)
        await set_user_logon_attrs(user, ctx.session, ctx.settings.TIMEZONE)

        server_sasl_creds = None
        if isinstance(self.authentication_choice, SaslSPNEGOAuthentication):
            server_sasl_creds = self.authentication_choice.server_sasl_creds

        yield BindResponse(
            result_code=LDAPCodes.SUCCESS,
            server_sasl_creds=server_sasl_creds,
        )


class UnbindRequest(BaseRequest):
    """Remove user from ldap_session."""

    PROTOCOL_OP: ClassVar[int] = ProtocolRequests.UNBIND

    @classmethod
    def from_data(
        cls,
        data: dict[str, list[ASN1Row]],  # noqa: ARG003
    ) -> "UnbindRequest":
        """Unbind request has no body."""
        return cls()

    async def handle(
        self,
        ctx: LDAPUnbindRequestContext,
    ) -> AsyncGenerator[BaseResponse, None]:
        """Handle unbind request, no need to send response."""
        await ctx.ldap_session.delete_user()
        return  # declare empty async generator and exit
        yield  # type: ignore
