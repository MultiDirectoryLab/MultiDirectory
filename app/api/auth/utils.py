"""Auth utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from functools import wraps
from ipaddress import IPv4Address, IPv6Address
from typing import Callable

from dishka.integrations.fastapi import inject
from fastapi import HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.objects import OperationEvent
from ldap_protocol.policies.audit_policy import (
    AuditEventBuilder,
    RedisAuditDAO,
)
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.utils.queries import set_last_logon_user
from models import User


async def create_and_set_session_key(
    user: User,
    session: AsyncSession,
    settings: Settings,
    response: Response,
    storage: SessionStorage,
    ip: IPv4Address | IPv6Address,
    user_agent: str,
) -> None:
    """Create and set access and refresh tokens.

    Update the user's last logon time and set the appropriate cookies
    in the response.

    :param User user: db user
    :param AsyncSession session: db session
    :param Settings settings: app settings
    :param Response response: fastapi response object
    """
    await set_last_logon_user(user, session, settings.TIMEZONE)

    key = await storage.create_session(
        user.id,
        settings,
        extra_data={
            "ip": str(ip),
            "user_agent": storage.get_user_agent_hash(user_agent),
        },
    )

    response.set_cookie(
        key="id",
        value=key,
        httponly=True,
        expires=storage.key_ttl,
    )


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
            request: Request = kwargs.get("request")  # type: ignore
            settings: Settings = kwargs.get("settings")  # type: ignore
            redis_client: RedisAuditDAO = (
                await request.state.dishka_container.get(RedisAuditDAO)
            )
            to_process_event = await redis_client.is_event_processing_enabled(
                event_type
            )

            username = ""
            target = None
            if event_type == OperationEvent.BIND:
                username = kwargs.get("form").username  # type: ignore
            elif event_type == OperationEvent.CHANGE_PASSWORD:
                username = kwargs.get("current_user").user_principal_name  # type: ignore
                target = kwargs.get("identity")

            if to_process_event:
                error_code = None
                error_message = None
                is_success_request = False

            try:
                result = await endpoint_func(*args, **kwargs)
            except HTTPException as error:
                if error.status_code == status.HTTP_426_UPGRADE_REQUIRED:
                    to_process_event = False

                if to_process_event:
                    error_code = error.status_code
                    error_message = error.detail

                raise

            except Exception:
                raise

            else:
                response = result
                if to_process_event:
                    is_success_request = True

                    if event_type == OperationEvent.AFTER_2FA:
                        username, response = result

                        if not username:
                            is_success_request = False

                return response

            finally:
                if to_process_event:
                    event_log = AuditEventBuilder.from_http_request(
                        request,
                        event_type=event_type,
                        username=username,
                        is_success_request=is_success_request,
                        settings=settings,
                        target=target,  # type: ignore
                        error_code=error_code,
                        error_message=error_message,
                    )
                    asyncio.create_task(
                        redis_client.add_audit_event(
                            event=event_log,
                            stream_name=settings.EVENT_STREAM_NAME,
                        )
                    )

        return wrapper

    return decorator
