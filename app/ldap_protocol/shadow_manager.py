"""ShadowManager: Class for encapsulating authentication business logic.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from enums import MFAFlags
from ldap_protocol.multifactor import LDAPMultiFactorAPI, MultifactorAPI
from ldap_protocol.objects import OperationEvent
from ldap_protocol.policies.audit.monitor import AuditMonitor
from ldap_protocol.policies.network_policy import get_user_network_policy
from ldap_protocol.policies.password_policy import (
    PasswordPolicySchema,
    post_save_password_actions,
)
from ldap_protocol.utils.queries import get_user
from security import get_password_hash


class UserNotFoundError(Exception):
    """Exception raised when user is not found in the database."""


class NetworkPolicyNotFoundError(Exception):
    """Exception raised when network policy is not found for the user."""


class AuthenticationError(Exception):
    """Exception raised for authentication errors."""


class PasswordPolicyError(Exception):
    """Exception raised for password policy validation errors."""

    def __init__(self, errors: list[str]) -> None:
        """Initialize PasswordPolicyError with validation errors."""
        self.errors = errors


class ShadowManager:
    """ShadowManager for managing shadow accounts."""

    def __init__(
        self,
        session: AsyncSession,
        mfa_api: LDAPMultiFactorAPI,
        monitor: AuditMonitor,
    ) -> None:
        """Initialize ShadowManager with an SQLAlchemy session."""
        self._session = session
        self._mfa_api = mfa_api
        self._monitor = monitor

    def __getattribute__(self, name: str) -> object:
        """Intercept attribute access to add session management."""
        attr = super().__getattribute__(name)

        if name == "proxy_request":

            async def wrapped_proxy_request(
                principal: str,
                ip: IPv4Address,
            ) -> None:
                """Wrap the proxy_request method to manage session."""
                self._monitor.event_type = OperationEvent.KERBEROS_AUTH
                self._monitor.username = principal
                self._monitor.ip = ip
                try:
                    return await attr(principal, ip)
                except (
                    UserNotFoundError,
                    NetworkPolicyNotFoundError,
                    AuthenticationError,
                ) as exc:
                    self._monitor.set_error_message(exc)
                    raise exc
                finally:
                    await self._monitor.track_audit_event()

            return wrapped_proxy_request

        elif name == "change_password":

            async def wrapped_change_password(
                principal: str,
                new_password: str,
            ) -> None:
                """Wrap the change_password method to manage session."""
                self._monitor.event_type = (
                    OperationEvent.CHANGE_PASSWORD_KERBEROS
                )
                self._monitor.username = principal
                try:
                    return await attr(principal, new_password)
                except (
                    UserNotFoundError,
                    PasswordPolicyError,
                ) as exc:
                    self._monitor.set_error_message(exc)
                    raise exc
                finally:
                    await self._monitor.track_audit_event()

            return wrapped_change_password
        return attr

    async def proxy_request(self, principal: str, ip: IPv4Address) -> None:
        """Proxy a request to the shadow account.

        Args:
            principal (str): The user principal name.
            ip (IPv4Address): The IP address of the request.

        Raises:
            UserNotFoundError: If the user is not found in the database.
            NetworkPolicyNotFoundError: If policy is not found for the user.
            AuthenticationError: If the authentication fails.

        """
        user = await get_user(self._session, principal)

        if not user:
            raise UserNotFoundError(
                f"User {principal} not found in the database.",
            )

        network_policy = await get_user_network_policy(
            ip,
            user,
            self._session,
        )

        if network_policy is None or not network_policy.is_kerberos:
            raise NetworkPolicyNotFoundError(
                f"Network policy not found for user {principal}.",
            )

        if not self._mfa_api or network_policy.mfa_status == MFAFlags.DISABLED:
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
                if await self._mfa_api.ldap_validate_mfa(
                    user.user_principal_name,
                    None,
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

        raise AuthenticationError("Authentication failed.")

    async def change_password(
        self,
        principal: str,
        new_password: str,
    ) -> None:
        """Synchronize the password for the shadow account.

        Args:
            principal (str): The user principal name.
            new_password (str): The new password to set.

        Raises:
            UserNotFoundError: If the user is not found in the database.
            PasswordPolicyError: If the new password not comply with policy.

        """
        user = await get_user(self._session, principal)

        if not user:
            raise UserNotFoundError(
                f"User {principal} not found in the database.",
            )

        policy = await PasswordPolicySchema.get_policy_settings(self._session)
        errors = await policy.validate_password_with_policy(new_password, user)

        if errors:
            raise PasswordPolicyError(errors)

        user.password = get_password_hash(new_password)
        await post_save_password_actions(user, self._session)
