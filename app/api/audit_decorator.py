"""Audit decorator for tracking events.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from functools import wraps
from typing import Callable

from dishka.integrations.fastapi import inject
from fastapi import HTTPException, Request, Response, status

from api.auth.utils import get_ip_from_request, get_user_agent_from_request
from config import Settings
from ldap_protocol.objects import OperationEvent
from ldap_protocol.policies.audit.audit_use_case import AuditUseCase
from ldap_protocol.policies.audit.events.factory import (
    RawAuditEventBuilderRedis,
)


async def _get_dependencies(
    kwargs: dict,
) -> tuple[Request, "Settings", AuditUseCase]:
    """Extract dependencies from kwargs."""
    request: Request = kwargs.get("request")  # type: ignore
    settings: Settings = await request.state.dishka_container.get(Settings)
    audit_use_case: AuditUseCase = await request.state.dishka_container.get(
        AuditUseCase,
    )
    return request, settings, audit_use_case


def _extract_event_data(
    event_type: OperationEvent,
    kwargs: dict,
) -> tuple[str, str | None]:
    """Extract username and target from kwargs based on event type."""
    username = ""
    target = None

    if event_type == OperationEvent.BIND:
        username = kwargs.get("form").username  # type: ignore
    elif event_type == OperationEvent.CHANGE_PASSWORD:
        username = kwargs.get("current_user").user_principal_name  # type: ignore
        target = kwargs.get("identity")
    elif event_type in {
        OperationEvent.KERBEROS_AUTH,
        OperationEvent.CHANGE_PASSWORD_KERBEROS,
    }:
        username = kwargs.get("principal")  # type: ignore

    return username, target


def _handle_error(
    error: HTTPException,
    to_process_event: bool,
    event_type: OperationEvent,
) -> tuple[bool, int | None, str | None]:
    """Handle HTTPException and extract error details for audit logging."""
    if (
        error.status_code == status.HTTP_426_UPGRADE_REQUIRED
        or not to_process_event
    ):
        return False, None, None

    error_code = error.status_code
    error_message = error.detail

    if event_type == OperationEvent.KERBEROS_AUTH:
        if error_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
            error_message = "User not found"
        elif error_code == status.HTTP_403_FORBIDDEN:
            error_message = "Network policy not found"
        elif error_code == status.HTTP_401_UNAUTHORIZED:
            error_message = "2FA error"

    if (
        event_type == OperationEvent.CHANGE_PASSWORD_KERBEROS
        and error_code == status.HTTP_404_NOT_FOUND
    ):
        error_message = "User not found"

    return to_process_event, error_code, error_message


def track_audit_event(event_type: OperationEvent) -> Callable:
    """Decorate endpoint to track audit events of specified type."""

    def decorator(endpoint_func: Callable) -> Callable:
        """Wrap endpoint function with audit event tracking logic."""

        @wraps(endpoint_func)
        @inject
        async def wrapper(
            *args: tuple,
            **kwargs: dict,
        ) -> Response:
            """Process request while tracking audit event."""
            (
                request,
                settings,
                audit_use_case,
            ) = await _get_dependencies(kwargs)
            to_process_event = (
                await audit_use_case.check_event_processing_enabled(
                    event_type,
                )
            )

            username, target = _extract_event_data(event_type, kwargs)

            if to_process_event:
                error_code = None
                error_message = None
                is_success_request = False

            try:
                response = await endpoint_func(*args, **kwargs)
            except HTTPException as error:
                to_process_event, error_code, error_message = _handle_error(
                    error,
                    to_process_event,
                    event_type,
                )
                raise

            else:
                if event_type == OperationEvent.AFTER_2FA:
                    username = request.state.username

                if to_process_event:
                    is_success_request = True

                return response

            finally:
                if to_process_event:
                    ip = get_ip_from_request(request)
                    user_agent = get_user_agent_from_request(request)
                    event_log = RawAuditEventBuilderRedis.from_http_request(
                        ip,
                        user_agent=user_agent,
                        event_type=event_type,
                        username=username,
                        is_success_request=is_success_request,
                        settings=settings,
                        target=target,
                        error_code=error_code,
                        error_message=error_message,
                    )
                    asyncio.create_task(
                        audit_use_case.manager.send_event(event=event_log),
                    )

        return wrapper

    return decorator
