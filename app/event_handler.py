"""Event Handler.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import json
import operator
import os
import socket
from typing import Any, Callable

from dishka import AsyncContainer, Scope
from loguru import logger
from redis_client import RedisClient
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defaultload

from config import Settings
from ldap_protocol.dependency import resolve_deps
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.objects import OperationEvent
from models import AuditPolicy, AuditPolicyTrigger

operations: dict[str, Callable] = {
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
    "==": operator.eq,
    "!=": operator.ne,
    "&": operator.and_,
    "|": operator.or_,
    "^": operator.xor,
    "<<": operator.lshift,
    ">>": operator.rshift,
    "~": operator.invert,
}


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

    def _check_modify_event(
        self, trigger: AuditPolicyTrigger, event: dict
    ) -> bool:
        """Check if event is suitable for modify trigger."""
        if (
            trigger.object_class
            not in event["help_data"]["after_attrs"]["objectclass"]
        ):
            return False

        if trigger.additional_info is None:
            return True  # type: ignore

        for change in event["request"]["context"]["changes"]:
            if (
                change["modification"]["type"]
                in trigger.additional_info["change_attributes"]
            ):
                break
        else:
            return False

        if len(trigger.additional_info.keys()) == 1:
            return True

        change_attribute = trigger.additional_info["change_attributes"][0]

        if change_attribute not in event["help_data"]["after_attrs"]:
            raise ValueError

        if change_attribute in {"useraccountcontrol", "pwdlastset"}:
            first_value = int(
                event["help_data"]["after_attrs"][change_attribute][0]
            )
            second_value = trigger.additional_info["value"]
        elif change_attribute in {"member", "memberof"}:
            first_value = event["help_data"]["before_attrs"][change_attribute]
            second_value = event["help_data"]["after_attrs"][change_attribute]
        else:
            raise ValueError

        operation = trigger.additional_info["operation"]
        op = operations[operation]
        result = trigger.additional_info["result"]

        return bool(op(first_value, second_value)) == result

    def is_match_trigger(
        self, trigger: AuditPolicyTrigger, event: dict
    ) -> bool:
        """Check if event is suitable for policy."""
        if event["protocol"].endswith("LDAP"):
            if event["request"]["protocol_op"] == OperationEvent.MODIFY:
                return self._check_modify_event(trigger, event)

            elif event["request"]["protocol_op"] == OperationEvent.EXTENDED:
                return (
                    trigger.additional_info["oid"]
                    == event["request"]["context"]["request_name"]
                )

            return trigger.additional_info is None

        else:
            raise ValueError

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

        triggers = (
            await session.scalars(
                select(AuditPolicyTrigger)
                .join(AuditPolicyTrigger.audit_policies)
                .where(
                    AuditPolicy.is_enabled.is_(True),
                    AuditPolicyTrigger.operation_code == operation_code,
                    AuditPolicyTrigger.operation_success.is_(is_success),
                    or_(
                        AuditPolicyTrigger.is_ldap.is_(is_ldap),
                        AuditPolicyTrigger.is_http.is_(is_http),
                    ),
                )
                .options(defaultload(AuditPolicyTrigger.audit_policies))
            )
        ).all()

        if not triggers:
            return None

        logger.debug(
            f"Suitable triggers: {[trigger.id for trigger in triggers]}"
        )

        matched_policies = []
        for trigger in triggers:
            if self.is_match_trigger(trigger, event_data):
                for policy in trigger.audit_policies:
                    if policy.is_enabled:
                        matched_policies.append(policy)

        logger.debug(
            f"Policies: {[policy.name for policy in matched_policies]}"
        )

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
