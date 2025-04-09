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
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.dependency import resolve_deps
from ldap_protocol.ldap_codes import LDAPCodes
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

    def is_success_request(self, responses: list[dict[str, Any]]) -> bool:
        """Check if the request was successful."""
        if not responses:
            return True

        return responses[-1]["context"]["result_code"] == LDAPCodes.SUCCESS

    def _check_triggers(self, policy: AuditPolicy, event: dict) -> bool:
        """Check if event triggers match policy."""
        event_triggers = list()
        for protocol in policy.triggers:
            if protocol in event["help_data"]:  # noqa
                if protocol == "LDAP":
                    for attr_name, attr_list in policy.triggers[
                        protocol
                    ].items():  # noqa
                        if attr_name in event["help_data"][protocol]:
                            for attr in attr_list:
                                event_triggers.append(
                                    attr
                                    in event["help_data"][protocol][attr_name]
                                )  # noqa

        return all(event_triggers)

    def _check_changes(self, policy: AuditPolicy, event: dict) -> bool:
        """Check if event changes match policy."""
        if policy.changes is None:
            return True

        for protocol in policy.changes:
            if protocol in event["help_data"]:
                if protocol == "LDAP":
                    return False

        return True

    def is_match_policy(self, policy: AuditPolicy, event: dict) -> bool:
        """Check if event is suitable for policy."""
        from loguru import logger

        logger.debug(f"name - {policy.name}")
        logger.debug(
            f"_check_triggers - {(self._check_triggers(policy, event),)}"
        )
        return all(
            [
                self._check_triggers(policy, event),
                self._check_changes(policy, event),
            ]
        )

    async def get_event_by_data(
        self,
        event_data: dict[str, Any],
        session: AsyncSession,
    ) -> AuditPolicy | None:
        """Check if the event is valid."""
        is_ldap = event_data["protocol"] == "TCP_LDAP"
        is_http = event_data["protocol"] == "HTTP_LDAP"
        is_success = self.is_success_request(event_data["responses"])
        operation_code = event_data["request"]["protocol_op"]

        policies = (
            await session.scalars(
                select(AuditPolicy).where(
                    AuditPolicy.is_enabled.is_(True),
                    or_(
                        AuditPolicy.is_ldap.is_(is_ldap),
                        AuditPolicy.is_http.is_(is_http),
                    ),
                    AuditPolicy.operation_success.is_(is_success),
                    AuditPolicy.operation_code == operation_code,
                ),
            )
        ).all()

        if not policies:
            return None

        logger.debug(
            f"Suitable policies: {[policy.name for policy in policies]}"
        )

        for policy in policies:
            if self.is_match_policy(policy, event_data):
                return policy

        return None

    async def normalize_event_data(
        self,
        event_data: dict[str, Any],
        policy: AuditPolicy,
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Normalize event data."""
        return {}

    async def handle_event(
        self,
        event_data: dict[str, Any],
        event_id: str,
        session: AsyncSession,
        redis_client: RedisClient,
    ) -> None:
        """Handle an event."""
        if event_data["request"]["protocol_op"] != 3:
            logger.debug(f"Event data: {event_data}")

        policy = await self.get_event_by_data(event_data, session)

        if policy is None:
            await redis_client.ack_message(
                self.event_stream,
                self.group_name,
                event_id,
            )
            await redis_client.remove(self.event_stream, event_id)
            return

        normalize_event_data = await self.normalize_event_data(
            event_data=event_data,
            policy=policy,
            session=session,
        )
        logger.debug(f"Normalized event data: {normalize_event_data}")

        # await send_event_to_redis(
        #     redis_client=redis_client,
        #     stream_name=self.event_stream,
        #     event_data=normalize_event_data,
        # )
        await redis_client.ack_message(
            self.event_stream,
            self.group_name,
            event_id,
        )
        await redis_client.remove(self.event_stream, event_id)

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
                                temp_value = value.decode()

                                if temp_key in {
                                    "responses",
                                    "request",
                                    "help_data",
                                }:
                                    temp_value = json.loads(temp_value)
                                elif temp_key == "datetime":
                                    temp_value = float(temp_value)  # type: ignore

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
