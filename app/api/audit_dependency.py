"""Audit decorator for tracking events.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from typing import AsyncIterator

from fastapi import HTTPException, Request, Response, status

from api.auth.utils import get_ip_from_request, get_user_agent_from_request
from config import Settings
from ldap_protocol.objects import OperationEvent
from ldap_protocol.policies.audit.audit_use_case import AuditUseCase
from ldap_protocol.policies.audit.events.factory import (
    RawAuditEventBuilderRedis,
)


async def _get_dependencies(
    request: Request,
) -> tuple[OperationEvent, Settings, AuditUseCase]:
    """Extract dependencies from kwargs."""
    settings: Settings = await request.state.dishka_container.get(Settings)
    audit_use_case: AuditUseCase = await request.state.dishka_container.get(
        AuditUseCase,
    )
    event_type = request.state.event_type

    return event_type, settings, audit_use_case


def _extract_event_data(
    event_type: OperationEvent,
    request: Request,
) -> tuple[str, str | None]:
    """Extract username and target from kwargs based on event type."""
    username = ""
    target = None

    if event_type in {OperationEvent.BIND, OperationEvent.AFTER_2FA}:
        username = request.state.username
    elif event_type == OperationEvent.CHANGE_PASSWORD:
        username = request.state.current_user.user_principal_name
        target = request.state.identity
    elif event_type in {
        OperationEvent.KERBEROS_AUTH,
        OperationEvent.CHANGE_PASSWORD_KERBEROS,
    }:
        username = request.state.principal

    return username, target


def _handle_error(
    response: Response,
    event_type: OperationEvent,
    error: Exception | None = None,
) -> tuple[bool, int | None, str | None]:
    """Handle HTTPException and extract error details for audit logging."""
    if (
        response.status_code == status.HTTP_426_UPGRADE_REQUIRED
        and event_type == OperationEvent.BIND
    ):
        return False, None, None

    error_code = response.status_code
    error_message = (
        error.detail if isinstance(error, HTTPException) else str(error)
    )

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

    return True, error_code, error_message


def _get_context(
    event_type: OperationEvent,
    target: str | None,
    error_code: int | None,
    error_message: str | None,
    user_agent: str | None,
) -> dict[str, dict[str, str | int]]:
    """Construct context for audit event based on event type and details."""
    context: dict[str, dict[str, str | int]] = {"details": {}}

    if user_agent:
        context["details"]["user-agent"] = user_agent
    if event_type == OperationEvent.BIND:
        context["details"]["auth_choice"] = "API"

    if error_code is not None:
        context["details"]["error_code"] = error_code
    if error_message is not None:
        context["details"]["error_message"] = error_message
    if target is not None:
        context["details"]["target"] = target

    return context


def is_successful_response(
    response: Response,
    event_type: OperationEvent,
    error: Exception | None = None,
) -> bool:
    """Check if the response indicates an error."""
    if error is not None:
        return False

    if response.status_code == status.HTTP_200_OK:
        return True

    if event_type == OperationEvent.KERBEROS_AUTH:
        return response.status_code in {
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_401_UNAUTHORIZED,
        }

    if event_type == OperationEvent.AFTER_2FA:
        if response.status_code != status.HTTP_302_FOUND:
            return False

        return response.headers.get("location") == "/"

    return False


async def _track_audit_event(
    request: Request,
    response: Response,
    error: Exception | None = None,
) -> None:
    (
        event_type,
        settings,
        audit_use_case,
    ) = await _get_dependencies(request)

    to_process_event = await audit_use_case.check_event_processing_enabled(
        event_type,
    )

    if not to_process_event:
        return

    error_code = None
    error_message = None
    is_success_request = False
    username, target = _extract_event_data(event_type, request)

    if not is_successful_response(response, event_type, error):
        to_process_event, error_code, error_message = _handle_error(
            response,
            event_type,
            error,
        )

    else:
        is_success_request = True

    if to_process_event:
        ip = get_ip_from_request(request)
        user_agent = get_user_agent_from_request(request)

        context = _get_context(
            event_type,
            target,
            error_code,
            error_message,
            user_agent,
        )

        event_log = RawAuditEventBuilderRedis.from_http_request(
            ip,
            event_type=event_type,
            username=username,
            is_success_request=is_success_request,
            settings=settings,
            context=context,
        )
        asyncio.create_task(
            audit_use_case.manager.send_event(event=event_log),
        )


async def track_audit_event(
    request: Request,
    response: Response,
) -> AsyncIterator[None]:
    """Process request while tracking audit event."""
    try:
        yield
    except Exception as error:
        await _track_audit_event(request, response, error)
        raise error
    else:
        await _track_audit_event(request, response)
