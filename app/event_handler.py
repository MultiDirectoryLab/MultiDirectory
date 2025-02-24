"""Event Handler.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import json
import os
import socket
from typing import Any

from dishka import AsyncContainer, Scope
from loguru import logger
from redis_client import RedisClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.dependency import resolve_deps
from ldap_protocol.utils.helpers import send_event_to_redis
from models import AuditPolicy


class EventHandler:
    """Event handler."""

    def __init__(self, settings: Settings, container: AsyncContainer) -> None:
        """Initialize the event handler."""
        self.container = container
        self.group_name = settings.EVENT_HANLDER_GROUP
        self.event_stream = settings.EVENT_STREAM_NAME
        self.settings = settings
        self.consumer_name = os.getenv("HOSTNAME", socket.gethostname())

    async def is_event_valid(
        self, event_data: dict[str, Any],
        session: AsyncSession,
    ) -> bool:
        """Check if the event is valid."""

        policies = await session.scalars(
            select(AuditPolicy)
            .where(AuditPolicy.is_enabled == True),  # noqa: E712
        )
        is_ldap = event_data['protocol'] == 'LDAP'
        is_http = event_data['protocol'] == 'HTTP'

        suitable_policies = [
            policy
            for policy in policies
            if all([
                policy.is_ldap == is_ldap or policy.is_http == is_http,
                policy.operation_code == event_data['request']['protocol_op'],
            ])
        ]

        suitable_police_names = [policy.name for policy in suitable_policies]

        logger.critical(f"Suitable policies: {suitable_police_names}")

        return False

    async def normalize_event_data(
        self, event_data: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Normalize event data."""
        return {}

    async def handle_event(
        self, event_data: dict[str, Any],
        event_id: str,
        session: AsyncSession,
        redis_client: RedisClient,
    ) -> None:
        """Handle an event."""
        logger.debug(f"Event data: {event_data}")

        if not (await self.is_event_valid(event_data, session)):
            await redis_client.ack_message(
                self.event_stream,
                self.group_name,
                event_id,
            )
            await redis_client.remove(self.event_stream, event_id)
            return

        normalize_event_data = await self.normalize_event_data(
            event_data=event_data,
            session=session,
        )
        logger.debug(f"Normalized event data: {normalize_event_data}")

        await send_event_to_redis(
            redis_client=redis_client,
            stream_name=self.event_stream,
            event_data=normalize_event_data,
        )

    async def read_stream(self) -> None:
        """Read messages from the stream."""
        redis_client: RedisClient = await self.container.get(RedisClient)
        await redis_client.create_consumer_group(
            self.event_stream,
            self.group_name,
        )
        while True:
            try:
                events = await redis_client.read(
                    stream_name=self.event_stream,
                    group_name=self.group_name,
                    consumer_name=self.consumer_name,
                    block=5000,
                )

                async with self.container(scope=Scope.REQUEST) as container:
                    for _, event_list in events:
                        for event_id, event_data in event_list:
                            decode_event_data = {}

                            for key, value in event_data.items():
                                temp_key = key.decode()

                                if temp_key in {'responses', 'request'}:
                                    temp_value = json.loads(value.decode())
                                else:
                                    temp_value = value.decode()

                                decode_event_data[temp_key] = temp_value

                            kwargs = await resolve_deps(
                                func=self.handle_event,
                                container=container,
                            )
                            await asyncio.gather(
                                self.handle_event(
                                    decode_event_data,
                                    event_id,
                                    **kwargs,
                                ),
                            )
            except ConnectionError:
                await asyncio.sleep(1)
            except Exception as exc:
                logger.exception(f"Error reading stream: {exc}")

    async def start(self) -> None:
        """Run the event handler."""
        try:
            await self.read_stream()
        finally:
            await self.container.close()


__all__ = ["EventHandler"]
