"""Audit policy monitor.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.utils import get_ip_from_request, get_user_agent_from_request
from config import Settings
from ldap_protocol.objects import OperationEvent
from ldap_protocol.policies.audit.audit_use_case import AuditUseCase
from ldap_protocol.policies.audit.events.factory import (
    RawAuditEventBuilderRedis,
)
from ldap_protocol.session_storage import SessionStorage
from models import User


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
        audit_use_case: AuditUseCase,
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
