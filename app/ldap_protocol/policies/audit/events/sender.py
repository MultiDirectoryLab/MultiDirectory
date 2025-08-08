"""Event sender.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ioc import AuditLogger
from ldap_protocol.policies.audit.audit_use_case import AuditUseCase
from ldap_protocol.policies.audit.dataclasses import AuditDestinationDTO

from .dataclasses import NormalizedAuditEvent
from .managers import NormalizedAuditManager
from .service_senders import senders

MAX_RETRY_COUNT = 3


class AuditEventSenderManager:
    """Audit event manager."""

    def __init__(  # noqa: D107
        self,
        normalized_audit_manager: NormalizedAuditManager,
        session: AsyncSession,
        normalized_class: type[NormalizedAuditEvent],
        settings: Settings,
        audit_logger: AuditLogger,
        audit_use_case: AuditUseCase,
    ) -> None:
        self._normalized_audit_manager = normalized_audit_manager
        self._session = session
        self._normalized_class = normalized_class
        self._settings = settings
        self._audit_logger = audit_logger
        self._audit_use_case = audit_use_case

    async def _should_delay_event_retry(
        self,
        event: NormalizedAuditEvent,
    ) -> bool:
        """Check if event retry should be delayed."""
        if not event.first_failed_at:
            return False

        if event.retry_count > MAX_RETRY_COUNT:
            return True

        first_failed_utc = event.first_failed_at.astimezone(timezone.utc)
        time_passed = datetime.now(tz=timezone.utc) - first_failed_utc

        match event.retry_count:
            case 1:
                return time_passed < timedelta(
                    minutes=self._settings.AUDIT_FIRST_RETRY_TIME,
                )
            case 2:
                return time_passed < timedelta(
                    minutes=self._settings.AUDIT_SECOND_RETRY_TIME,
                )
            case 3:
                return time_passed < timedelta(
                    minutes=self._settings.AUDIT_THIRD_RETRY_TIME,
                )
            case _:
                return False

    async def _send_to_destination(
        self,
        event: NormalizedAuditEvent,
        destination: AuditDestinationDTO,
        active_destination_ids: list[int],
    ) -> None:
        """Send event to a single audit destination."""
        sender = senders[destination.service_type](destination)

        if destination.id is None:
            raise ValueError(
                f"Destination ID is None for {destination.service_type}.",
            )

        if event.delivery_status.get(destination.id, False):
            return

        if await self._should_delay_event_retry(event):
            return

        try:
            await sender.send(event)
            event.delivery_status[destination.id] = True
        except Exception as error:
            logger.error(f"Sending error to {destination.id}: {error}")
            event.delivery_status[destination.id] = False

            if event.first_failed_at is None:
                event.first_failed_at = datetime.now(tz=timezone.utc)

            event.retry_count += 1
        finally:
            event.delivery_status = {
                k: v
                for k, v in event.delivery_status.items()
                if k in active_destination_ids
            }

    async def _remove_matching_event(
        self,
        event: NormalizedAuditEvent,
    ) -> None:
        """Remove processed or failed events."""
        to_delete = False

        if event.first_failed_at:
            first_failed_utc = event.first_failed_at.astimezone(
                timezone.utc,
            )
            time_passed = datetime.now(tz=timezone.utc) - first_failed_utc

            if time_passed > timedelta(
                minutes=self._settings.AUDIT_THIRD_RETRY_TIME,
            ) and (event.retry_count > MAX_RETRY_COUNT):
                self._audit_logger.info(f"{event.id} {asdict(event)}")
                to_delete = True

        if event.delivery_status and all(
            event.delivery_status.values(),
        ):
            to_delete = True

        await self._normalized_audit_manager.delete_event(event.id)  # type: ignore

        if not to_delete:
            await self._normalized_audit_manager.send_event(event)  # type: ignore

    async def send_event(
        self,
        event: NormalizedAuditEvent,
    ) -> None:
        destinations = await self._audit_use_case.get_active_destinations()
        active_destination_ids = [dest.id for dest in destinations]
        if not destinations:
            return

        from loguru import logger

        logger.critical(event)

        await asyncio.gather(
            *[
                self._send_to_destination(
                    event,
                    destination,
                    active_destination_ids,  # type: ignore
                )
                for destination in destinations
            ],
        )

        await self._remove_matching_event(event)

    async def run(self) -> None:
        """Run event sender."""
        await self._normalized_audit_manager.setup_reading()

        while True:
            for event in await self._normalized_audit_manager.read_events():
                await self.send_event(event)
            await asyncio.sleep(10)
