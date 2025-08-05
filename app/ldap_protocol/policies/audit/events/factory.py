"""Raw audit event factory.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import Any, Generic, TypeVar

from config import Settings
from ldap_protocol.ldap_requests import BaseRequest
from ldap_protocol.ldap_responses import BaseResponse
from ldap_protocol.objects import OperationEvent

from .dataclasses import RawAuditEvent, RawAuditEventRedis

T = TypeVar("T", bound=RawAuditEvent)


class AuditEventBuilder(Generic[T]):
    """Builder for constructing AuditEvent objects from various request types.

    This class provides factory methods to create standardized audit events
    from different types of network requests (LDAP, HTTP etc.).
    """

    @classmethod
    def _class(cls) -> type[T]:
        """Return the class type of the audit event."""
        return cls.__args__[0]  # type: ignore

    @classmethod
    def from_ldap_request(
        cls,
        request: "BaseRequest",
        responses: list["BaseResponse"],
        username: str,
        ip: IPv4Address | IPv6Address,
        context: dict[str, Any],
        settings: "Settings",
        protocol: str,
    ) -> T:
        """Construct an AuditEvent from LDAP request data."""
        return cls._class()(
            request=request.model_dump(),
            responses=[r.model_dump() for r in responses],
            protocol=protocol,
            request_code=OperationEvent(request.PROTOCOL_OP),
            context=context,
            username=username,
            source_ip=ip,
            dest_port=settings.PORT,
            service_name=settings.SERVICE_NAME,
        )

    @classmethod
    def from_http_request(
        cls,
        ip: IPv4Address | IPv6Address,
        event_type: OperationEvent,
        username: str,
        is_success_request: bool,
        settings: "Settings",
        user_agent: str | None = None,
        target: str | None = None,
        error_code: int | None = None,
        error_message: str | None = None,
    ) -> T:
        """Construct an AuditEvent from HTTP request data."""
        context: dict[str, dict[str, str | int]] = {"details": {}}

        if user_agent:
            context["details"]["user-agent"] = user_agent
        if event_type == OperationEvent.BIND:
            context["details"]["auth_choice"] = "API"

        if error_code:
            context["details"]["error_code"] = error_code
        if error_message:
            context["details"]["error_message"] = error_message
        if target:
            context["details"]["target"] = target

        return cls._class()(
            request=dict(),
            responses=list(),
            protocol="API",
            request_code=event_type,
            context=context,
            username=username,
            source_ip=ip,
            dest_port=settings.HTTP_PORT,
            http_success_status=is_success_request,
            service_name=settings.SERVICE_NAME,
        )


RawAuditEventBuilderRedis = AuditEventBuilder[RawAuditEventRedis]
