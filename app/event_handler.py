"""Event Handler.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import operator
import os
import socket
from typing import Any, Callable

from dishka import AsyncContainer, Scope
from loguru import logger
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defaultload
from ulid import ULID

from audit_models import AuditLog
from config import Settings
from ioc import EventAsyncSession
from ldap_protocol.dependency import resolve_deps
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.objects import OperationEvent
from ldap_protocol.policies.audit_policy import AuditEvent, RedisAuditDAO
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
    """Handle incoming audit events and process them according to policies."""

    def __init__(
        self,
        settings: Settings,
        container: AsyncContainer,
    ) -> None:
        """Initialize event handler with settings and DI container."""
        self.container = container
        self.group_name = settings.EVENT_HANLDER_GROUP
        self.event_stream = settings.EVENT_STREAM_NAME
        self.settings = settings
        self.consumer_name = os.getenv("HANDLER_NAME", socket.gethostname())

    def _check_modify_event(
        self, trigger: AuditPolicyTrigger, event: AuditEvent
    ) -> bool:
        """Check if modify event matches trigger conditions."""
        if (
            trigger.object_class
            not in event.context["after_attrs"]["objectclass"]
        ):
            return False

        if trigger.additional_info is None:
            return True  # type: ignore

        for change in event.request["changes"]:
            if (
                change["modification"]["type"].lower()
                in trigger.additional_info["change_attributes"]
            ):
                break
        else:
            return False

        if len(trigger.additional_info.keys()) == 1:
            return True

        change_attribute = trigger.additional_info["change_attributes"][0]

        if change_attribute not in event.context["after_attrs"]:
            raise ValueError

        if change_attribute in {"useraccountcontrol", "pwdlastset"}:
            first_value = int(
                event.context["after_attrs"][change_attribute][0]
            )
            second_value = trigger.additional_info["value"]
        elif change_attribute in {"member", "memberof"}:
            first_value = event.context["before_attrs"][change_attribute]
            second_value = event.context["after_attrs"][change_attribute]
        else:
            raise ValueError

        operation = trigger.additional_info["operation"]
        op = operations[operation]
        result = trigger.additional_info["result"]

        return bool(op(first_value, second_value)) == result

    def _check_bind_event(self, event: AuditEvent) -> bool:
        """Verify if bind event is not SASL bind in progress."""
        return (
            event.responses[-1]["result_code"]
            != LDAPCodes.SASL_BIND_IN_PROGRESS
        )

    def _check_object_class(
        self, trigger: AuditPolicyTrigger, event: AuditEvent
    ) -> bool:
        """Check if event object class matches trigger object class."""
        return (
            trigger.object_class
            in event.context["before_attrs"]["objectclass"]
        )

    def is_match_trigger(
        self, trigger: AuditPolicyTrigger, event: AuditEvent
    ) -> bool:
        """Determine if event matches trigger conditions."""
        if event.request_code == OperationEvent.CHANGE_PASSWORD:
            return True

        if event.protocol == "API" and event.request_code in [
            OperationEvent.BIND,
            OperationEvent.AFTER_2FA,
        ]:
            return True

        if event.protocol.endswith("LDAP"):
            if event.request_code == OperationEvent.BIND:
                return self._check_bind_event(event)

            elif event.request_code == OperationEvent.MODIFY:
                return self._check_modify_event(trigger, event)

            elif event.request_code in [
                OperationEvent.ADD,
                OperationEvent.DELETE,
            ]:
                return self._check_object_class(trigger, event)

            elif event.request_code == OperationEvent.EXTENDED:
                return (
                    trigger.additional_info["oid"]
                    == event.request["request_name"]
                )

            return trigger.additional_info is None

        else:
            raise ValueError

    async def get_event_by_data(
        self,
        event_data: AuditEvent,
        session: AsyncSession,
    ) -> list[AuditPolicyTrigger]:
        """Find all policy triggers matching event data."""
        is_ldap = event_data.protocol == "TCP_LDAP"
        is_http = "API" in event_data.protocol

        operation_code = event_data.request_code
        matched_triggers: list[AuditPolicyTrigger] = []

        triggers = (
            await session.scalars(
                select(AuditPolicyTrigger)
                .join(AuditPolicyTrigger.audit_policy)
                .where(
                    AuditPolicy.is_enabled.is_(True),
                    AuditPolicyTrigger.operation_code == operation_code,
                    AuditPolicyTrigger.operation_success.is_(
                        event_data.is_event_successful()
                    ),
                    or_(
                        AuditPolicyTrigger.is_ldap.is_(is_ldap),
                        AuditPolicyTrigger.is_http.is_(is_http),
                    ),
                )
                .options(defaultload(AuditPolicyTrigger.audit_policy))
            )
        ).all()

        if not triggers:
            return matched_triggers

        logger.debug(
            f"Suitable triggers: {[trigger.id for trigger in triggers]}"
        )

        for trigger in triggers:
            if self.is_match_trigger(trigger, event_data):
                logger.debug(f"Matched policy: {trigger.audit_policy.name}")
                matched_triggers.append(trigger)

        return matched_triggers

    def _get_common_fields(
        self, event_data: AuditEvent, trigger: AuditPolicyTrigger
    ) -> dict:
        """Extract common fields from event data and trigger."""
        return {
            "username": event_data.username,
            "source_ip": str(event_data.source_ip),
            "dest_port": event_data.dest_port,
            "timestamp": event_data.timestamp,
            "hostname": event_data.hostname,
            "protocol": "API" if "API" in event_data.protocol else "LDAP",
            "event_type": trigger.audit_policy.name,
            "severity": trigger.audit_policy.severity,
            "policy_id": trigger.audit_policy.id,
            "operation_success": trigger.operation_success,
            "service_name": event_data.service_name,
        }

    def _enrich_ldap_details(
        self,
        event_data: AuditEvent,
        details: dict,
        trigger: AuditPolicyTrigger,
    ) -> None:
        """Add LDAP-specific details to event details."""
        if event_data.request_code == OperationEvent.MODIFY:
            details["target_dn"] = event_data.request["object"]

            if not trigger.additional_info["change_attributes"]:
                return

            change_attribute = trigger.additional_info["change_attributes"][0]
            if change_attribute in {"member", "memberof"}:
                first_value = set(
                    event_data.context["before_attrs"][change_attribute]
                )
                second_value = set(
                    event_data.context["after_attrs"][change_attribute]
                )
                if not first_value - second_value:
                    details["diff_groups"] = list(second_value - first_value)
                else:
                    details["diff_groups"] = list(first_value - second_value)
        elif event_data.request_code != OperationEvent.BIND:
            details["target_dn"] = event_data.request["entry"]

    def _prepare_details(
        self, event_data: AuditEvent, trigger: AuditPolicyTrigger
    ) -> dict:
        """Prepare base details structure from event data."""
        details = event_data.context.get("details", {})

        if "LDAP" in event_data.protocol:
            self._enrich_ldap_details(event_data, details, trigger)

        return details

    def _extract_error_info(self, event_data: AuditEvent) -> dict[str, str]:
        """Extract error information from failed event."""
        if "error_code" in event_data.context.get("details", {}):
            details = event_data.context["details"]
            return {
                "error_code": details["error_code"],
                "error_message": details["error_message"],
            }
        elif event_data.protocol.endswith("LDAP"):
            last_response = event_data.responses[-1]
            return {
                "error_code": last_response["result_code"],
                "error_message": last_response["message"],
            }
        return {}

    def normalize(
        self, event_data: AuditEvent, trigger: AuditPolicyTrigger
    ) -> dict[str, Any]:
        """Normalize event data according to trigger policy."""
        normalized = {
            **self._get_common_fields(event_data, trigger),
            "details": self._prepare_details(event_data, trigger),
        }

        if not trigger.operation_success:
            normalized["details"].update(self._extract_error_info(event_data))

        return normalized

    async def save_events(
        self,
        events: list[dict[str, Any]],
        session: EventAsyncSession,
    ) -> None:
        """Persist normalized events to database."""
        session.add_all(
            [
                AuditLog(
                    id=str(ULID.from_timestamp(event["timestamp"])),
                    content=event,
                )
                for event in events
            ]
        )
        await session.commit()

    async def handle_event(
        self,
        event_data: AuditEvent,
        event_id: str,
        session: AsyncSession,
        event_session: EventAsyncSession,
        redis_client: RedisAuditDAO,
    ) -> None:
        """Process single event through entire pipeline."""
        logger.debug(f"Event data: {event_data}")
        try:
            events = await self.get_event_by_data(event_data, session)

            if not events:
                return

            normalize_events = [
                self.normalize(event_data, policy) for policy in events
            ]

            logger.debug(
                f"Normalized events: {[event for event in normalize_events]}"
            )

            await self.save_events(normalize_events, event_session)
        finally:
            await redis_client.acknowledge_and_delete_event(
                self.event_stream, self.group_name, event_id
            )

    async def read_stream(self) -> None:
        """Continuously read and process events from Redis stream."""
        redis_client: RedisAuditDAO = await self.container.get(RedisAuditDAO)
        await redis_client.create_consumer_group(
            self.event_stream,
            self.group_name,
        )
        while True:
            try:
                events = await redis_client.read_events(
                    stream_name=self.event_stream,
                    group_name=self.group_name,
                    consumer_name=self.consumer_name,
                    block=5000,
                )

                async with self.container(scope=Scope.REQUEST) as container:
                    for _, event_list in events:
                        for event_id, event_data in event_list:
                            audit_event = AuditEvent.from_redis(event_data)
                            kwargs = await resolve_deps(
                                func=self.handle_event,
                                container=container,
                            )
                            await asyncio.gather(
                                self.handle_event(
                                    audit_event,
                                    event_id,
                                    **kwargs,
                                ),
                            )
            except ConnectionError:
                await asyncio.sleep(1)
            except Exception as exc:
                logger.exception(f"Error reading stream: {exc}")

    async def start(self) -> None:
        """Start event handler main processing loop."""
        try:
            await self.read_stream()
        finally:
            await self.container.close()


__all__ = ["EventHandler"]
