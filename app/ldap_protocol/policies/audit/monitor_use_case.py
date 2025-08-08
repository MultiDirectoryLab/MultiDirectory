"""Audit monitor use case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from functools import wraps
from ipaddress import IPv4Address, IPv6Address
from typing import Callable, TypeVar

from api.auth.schema import OAuth2Form
from api.exceptions.auth import (
    LoginFailedError,
    PasswordPolicyError,
    UnauthorizedError,
    UserNotFoundError,
)
from api.exceptions.mfa import (
    AuthenticationError,
    ForbiddenError,
    InvalidCredentialsError,
    MFARequiredError,
    MFATokenError,
    NetworkPolicyError,
)
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.multifactor import MFA_HTTP_Creds
from ldap_protocol.objects import OperationEvent

from .monitor import AuditMonitor

_T = TypeVar("_T", bound=Callable)


class AuditMonitorUseCase:
    """Use case for audit monitoring."""

    def __init__(self, monitor: AuditMonitor) -> None:
        """Initialize the use case with a monitor."""
        self._monitor = monitor

    def __getattribute__(self, name: str) -> object:
        """Intercept attribute access to add session management."""
        attr = super().__getattribute__(name)
        if not callable(attr):
            return attr

        if name == "callback_mfa":
            return self._wrap_callback_mfa(attr)
        elif name == "proxy_request":
            return self._wrap_proxy_request(attr)
        elif name == "login":
            return self._wrap_login(attr)
        elif name == "change_password":
            return self._wrap_change_password(attr)
        elif name == "reset_password":
            return self._wrap_reset_password(attr)
        return attr

    def _wrap_callback_mfa(
        self,
        attr: _T,
    ) -> _T:
        @wraps(attr)
        async def wrapped_callback_mfa(
            access_token: str,
            mfa_creds: MFA_HTTP_Creds,
            ip: IPv4Address | IPv6Address,
            user_agent: str,
        ) -> str:
            """Wrap callback_mfa to handle session management."""
            self._monitor.event_type = OperationEvent.AFTER_2FA
            self._monitor.ip = ip
            self._monitor.user_agent = user_agent
            try:
                key = await attr(
                    access_token,
                    mfa_creds,
                    ip,
                    user_agent,
                )
                self._monitor.username = key
                return key
            except (ForbiddenError, MFATokenError) as exc:
                self._monitor.set_error_message(exc)
                raise exc
            finally:
                await self._monitor.track_audit_event()

        return wrapped_callback_mfa  # type: ignore

    def _wrap_proxy_request(self, attr: _T) -> _T:
        @wraps(attr)
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
                InvalidCredentialsError,
                NetworkPolicyError,
                AuthenticationError,
            ) as exc:
                self._monitor.set_error_message(exc)
                raise exc
            finally:
                await self._monitor.track_audit_event()

        return wrapped_proxy_request  # type: ignore

    def _wrap_login(self, attr: _T) -> _T:
        @wraps(attr)
        async def wrapped_login(
            form: OAuth2Form,
            ip: IPv4Address | IPv6Address,
            user_agent: str,
        ) -> object:
            self._monitor.event_type = OperationEvent.BIND
            self._monitor.username = form.username
            self._monitor.ip = ip
            self._monitor.user_agent = user_agent
            try:
                return await attr(
                    form=form,
                    ip=ip,
                    user_agent=user_agent,
                )
            except (UnauthorizedError, LoginFailedError) as exc:
                self._monitor.set_error_message(exc)
                raise exc
            except MFARequiredError as exc:
                self._monitor.is_proc_enabled = False
                raise exc
            finally:
                await self._monitor.track_audit_event()

        return wrapped_login  # type: ignore

    def _wrap_change_password(self, attr: _T) -> _T:
        @wraps(attr)
        async def wrapped_change_password(
            principal: str,
            new_password: str,
        ) -> None:
            """Wrap the change_password method to manage session."""
            self._monitor.event_type = OperationEvent.CHANGE_PASSWORD_KERBEROS
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

        return wrapped_change_password  # type: ignore

    def _wrap_reset_password(self, attr: _T) -> _T:
        @wraps(attr)
        async def wrapped_reset_password(
            identity: str,
            new_password: str,
            kadmin: AbstractKadmin,
        ) -> None:
            self._monitor.event_type = OperationEvent.CHANGE_PASSWORD
            self._monitor.target = identity
            await self._monitor.set_username()
            try:
                return await attr(
                    identity=identity,
                    new_password=new_password,
                    kadmin=kadmin,
                )
            except (
                UserNotFoundError,
                PasswordPolicyError,
                KRBAPIError,
            ) as exc:
                self._monitor.set_error_message(exc)
                raise exc

            finally:
                await self._monitor.track_audit_event()

        return wrapped_reset_password  # type: ignore
