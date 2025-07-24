"""Event sender.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Sequence

from dishka import AsyncContainer, Scope
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ioc import AuditLogger, EventAsyncSession
from ldap_protocol.dependency import resolve_deps
from ldap_protocol.events.models import AuditLog
from models import AuditDestination

from .senders import senders


class AuditEventSenderManager:
    """Audit event manager."""

    container: AsyncContainer
    settings: Settings

    def __init__(  # noqa: D107
        self,
        container: AsyncContainer,
        settings: Settings,
    ) -> None:
        self.container = container
        self.settings = settings

    async def _should_skip_event_retry(self, event: AuditLog) -> bool:
        """Check if event should be skipped."""
        if not event.first_failed_at:
            return False

        if event.retry_count > 3:
            return True

        first_failed_utc = event.first_failed_at.astimezone(timezone.utc)
        time_passed = datetime.now(tz=timezone.utc) - first_failed_utc

        match event.retry_count:
            case 1:
                return time_passed < timedelta(
                    minutes=self.settings.AUDIT_FIRST_RETRY_TIME
                )
            case 2:
                return time_passed < timedelta(
                    minutes=self.settings.AUDIT_SECOND_RETRY_TIME
                )
            case 3:
                return time_passed < timedelta(
                    minutes=self.settings.AUDIT_THIRD_RETRY_TIME
                )
            case _:
                return False

    async def _send_to_destinations(
        self,
        events: Sequence[AuditLog],
        server: AuditDestination,
        active_destination_ids: list[int],
    ) -> None:
        """Send events to audit destinations."""
        sender = senders[server.service_type](server)

        for event in events:
            if event.server_delivery_status.get(server.id, False):
                continue

            if await self._should_skip_event_retry(event):
                continue

            try:
                await sender.send(event)
                event.server_delivery_status[server.id] = True
            except Exception as error:
                logger.error(f"Sending error to {server.id}: {error}")
                event.server_delivery_status[server.id] = False

                if event.first_failed_at is None:
                    event.first_failed_at = datetime.now(tz=timezone.utc)

                event.retry_count += 1
            finally:
                event.server_delivery_status = {
                    k: v
                    for k, v in event.server_delivery_status.items()
                    if k in active_destination_ids
                }

    async def _remove_matching_events(
        self,
        events: Sequence[AuditLog],
        event_session: EventAsyncSession,
        audit_logger: AuditLogger,
    ) -> None:
        """Remove processed or failed events."""
        for event in events:
            to_delete = False

            if event.first_failed_at:
                first_failed_utc = event.first_failed_at.astimezone(
                    timezone.utc
                )
                time_passed = datetime.now(tz=timezone.utc) - first_failed_utc

                if time_passed > timedelta(
                    minutes=self.settings.AUDIT_THIRD_RETRY_TIME
                ) or (event.retry_count > 3):
                    audit_logger.info(f"{event.id} {event.content}\n")
                    to_delete = True

            if event.server_delivery_status and all(
                event.server_delivery_status.values()
            ):
                to_delete = True

            if to_delete:
                await event_session.delete(event)

    async def send_events(
        self,
        session: AsyncSession,
        event_session: EventAsyncSession,
        audit_logger: AuditLogger,
    ) -> None:
        destinations = await session.scalars(
            select(AuditDestination).filter_by(is_enabled=True)
        )
        active_destination_ids = [
            destination.id for destination in destinations
        ]

        if not destinations:
            return

        events = (
            await event_session.scalars(
                select(AuditLog)
                .with_for_update(skip_locked=True)
                .limit(100)
                .order_by(AuditLog.id.asc())
            )
        ).all()

        for server in destinations:
            await self._send_to_destinations(
                events, server, active_destination_ids
            )

        await event_session.flush()
        await self._remove_matching_events(events, event_session, audit_logger)
        await event_session.commit()

    async def run(self) -> None:
        """Run event sender."""
        while True:
            async with self.container(scope=Scope.REQUEST) as container:
                kwargs = await resolve_deps(self.send_events, container)
                await self.send_events(**kwargs)
                await asyncio.sleep(10)
