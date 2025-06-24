"""ShadowMFAService and ShadowPasswordService: services for shadow_api logic.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from api.utils.exceptions import (
    ForbiddenError,
    MFAError,
    NotFoundError,
    PolicyError,
)
from ldap_protocol.multifactor import LDAPMultiFactorAPI, MultifactorAPI
from ldap_protocol.policies.network_policy import get_user_network_policy
from ldap_protocol.policies.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from ldap_protocol.utils.queries import get_user
from models import MFAFlags
from security import get_password_hash


class ShadowMFAService:
    """Service for handling MFA push in shadow_api."""

    def __init__(self, session: AsyncSession, mfa: LDAPMultiFactorAPI):
        """Initialize service dependencies.

        :param session: SQLAlchemy AsyncSession
        :param mfa: LDAPMultiFactorAPI
        """
        self.session = session
        self.mfa = mfa

    async def proxy_request(self, principal: str, ip: IPv4Address) -> None:
        """Proxy MFA push request for user.

        :param principal: str
        :param ip: IPv4Address
        :raises NotFoundError: if user not found
        :raises ForbiddenError: if policy not passed
        :raises MFAError: for MFA-specific errors
        """
        user = await get_user(self.session, principal)
        if not user:
            raise NotFoundError("User not found")
        network_policy = await get_user_network_policy(ip, user, self.session)
        if network_policy is None or not network_policy.is_kerberos:
            raise ForbiddenError("Kerberos policy not passed")
        if not self.mfa or network_policy.mfa_status == MFAFlags.DISABLED:
            return
        elif network_policy.mfa_status in (
            MFAFlags.ENABLED,
            MFAFlags.WHITELIST,
        ):
            if (
                network_policy.mfa_status == MFAFlags.WHITELIST
                and not network_policy.mfa_groups
            ):
                return
            try:
                if await self.mfa.ldap_validate_mfa(
                    user.user_principal_name, None
                ):
                    return
            except MultifactorAPI.MFAConnectError:
                logger.error("MFA connect error")
                if network_policy.bypass_no_connection:
                    return
            except MultifactorAPI.MFAMissconfiguredError:
                logger.error("MFA missconfigured error")
                return
            except MultifactorAPI.MultifactorError:
                logger.error("MFA service failure")
                if network_policy.bypass_service_failure:
                    return
        raise MFAError("MFA unauthorized")


class ShadowPasswordService:
    """Service for handling password synchronization in shadow_api."""

    def __init__(self, session: AsyncSession):
        """Initialize service dependencies.

        :param session: SQLAlchemy AsyncSession
        """
        self.session = session

    async def sync_password(self, principal: str, new_password: str) -> None:
        """Synchronize user password.

        :param principal: str
        :param new_password: str
        :raises NotFoundError: if user not found
        :raises PolicyError: if password policy not passed
        """
        user = await get_user(self.session, principal)
        if not user:
            raise NotFoundError("User not found")
        policy = await PasswordPolicySchema.get_policy_settings(self.session)
        errors = await policy.validate_password_with_policy(new_password, user)
        if errors:
            raise PolicyError(errors)
        user.password = get_password_hash(new_password)
        await post_save_password_actions(user, self.session)
