"""Audit policy monitor.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from functools import wraps
from ipaddress import IPv4Address, IPv6Address
from typing import Callable, TypeVar

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.schema import OAuth2Form
from api.auth.utils import get_ip_from_request, get_user_agent_from_request
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
from config import Settings
from ldap_protocol.kerberos import AbstractKadmin, KRBAPIError
from ldap_protocol.multifactor import MFA_HTTP_Creds
from ldap_protocol.objects import OperationEvent
from ldap_protocol.policies.audit.audit_use_case import AuditUseCase
from ldap_protocol.policies.audit.events.factory import (
    RawAuditEventBuilderRedis,
)
from ldap_protocol.session_storage import SessionStorage
from models import User

_T = TypeVar("_T", bound=Callable)


class AuditMonitor:
    """Monitor for managers."""

    event_type: OperationEvent
    username: str | None = None
    target: str | None = None
    error_message: str | None = None
    is_success_operation: bool = True
    ip: IPv4Address | IPv6Address | None = None
    user_agent: str | None = None
    is_proc_enabled: bool | None = None

    def __init__(
        self,
        session: AsyncSession,
        audit_use_case: "AuditUseCase",
        session_storage: SessionStorage,
        settings: Settings,
        request: Request,
    ) -> None:
        """Initialize the audit monitor with necessary components."""
        self._session = session
        self._audit_use_case = audit_use_case
        self._session_storage = session_storage
        self._settings = settings
        self._request = request

    async def set_username(self) -> None:
        """Get the username from the session."""
        session_key = self._request.cookies.get("id", "")

        user_id = await self._session_storage.get_user_id(
            self._settings,
            session_key,
            self.get_user_agent(),
            str(self.get_ip()),
        )

        user = await self._session.scalar(
            select(User).filter_by(id=user_id),
        )

        if not user:
            raise ValueError("User not found in session")

        self.username = user.user_principal_name or user.sam_accout_name

    def get_ip(self) -> IPv4Address | IPv6Address:
        """Get the IP address from the request."""
        if self.ip is None:
            self.ip = get_ip_from_request(self._request)
        return self.ip

    def get_user_agent(self) -> str:
        """Get the User-Agent from the request."""
        if self.user_agent is None:
            self.user_agent = get_user_agent_from_request(self._request)
        return self.user_agent

    async def get_proc_enabled(self) -> bool:
        """Check if the event needs to be processed."""
        if self.event_type is None:
            raise ValueError("Event type is not set")
        if self.is_proc_enabled is None:
            self.is_proc_enabled = (
                await self._audit_use_case.check_event_processing_enabled(
                    self.event_type,
                )
            )
        return self.is_proc_enabled

    def generate_details(self) -> dict[str, dict[str, str]]:
        """Generate details for the audit event."""
        details = {}

        if self.event_type not in {
            OperationEvent.CHANGE_PASSWORD_KERBEROS,
            OperationEvent.KERBEROS_AUTH,
        }:
            details["user_agent"] = self.get_user_agent()

        if self.target:
            details["target"] = self.target

        if self.error_message:
            details["error_message"] = self.error_message

        return {"details": details}

    def set_error_message(self, exc: Exception) -> None:
        """Get the error message from an exception."""
        self.error_message = str(exc)
        self.is_success_operation = False

    async def track_audit_event(self) -> None:
        """Track an audit policy event."""
        if not await self.get_proc_enabled():
            return

        if self.username is None:
            raise ValueError("Username is not set")

        details = self.generate_details()
        event = RawAuditEventBuilderRedis.from_http_request(
            self.get_ip(),
            event_type=self.event_type,
            username=self.username,
            is_success_request=self.is_success_operation,
            settings=self._settings,
            context=details,
        )
        await self._audit_use_case.manager.send_event(event)


class AuditMonitorUseCase:
    """Use case for audit monitoring."""

    def __init__(self, monitor: AuditMonitor) -> None:
        """Initialize the use case with a monitor."""
        self._monitor = monitor

    def wrap_callback_mfa(
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

    def wrap_proxy_request(self, attr: _T) -> _T:
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

    def wrap_login(self, attr: _T) -> _T:
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

    def wrap_change_password(self, attr: _T) -> _T:
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

    def wrap_reset_password(self, attr: _T) -> _T:
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
