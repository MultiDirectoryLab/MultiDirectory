"""Event Handler.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import operator
from typing import Callable

from dishka import AsyncContainer, Scope
from loguru import logger
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.dependency import resolve_deps
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.objects import OperationEvent
from models import AuditPolicy, AuditPolicyTrigger

from .adapter import AuditNormalizedAdapter, AuditRawAdapter
from .dataclasses import NormalizedEvent, RawEvent
from .normalizer import AuditEventNormalizer

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


class AuditEventHandler:
    """Handle incoming audit events and process them according to policies."""

    def __init__(
        self,
        container: AsyncContainer,
    ) -> None:
        """Initialize event handler with settings and DI container."""
        self.container = container

    def _check_modify_event(
        self,
        trigger: AuditPolicyTrigger,
        event: RawEvent,
    ) -> bool:
        """Check if modify event matches trigger conditions."""
        if (
            trigger.object_class
            not in event.context["after_attrs"]["objectclass"]
        ):
            return False

        if trigger.additional_info is None:
            return True

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
                event.context["after_attrs"][change_attribute][0],
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

    def _check_bind_event(self, event: RawEvent) -> bool:
        """Verify if bind event is not SASL bind in progress.

        SASL_BIND_IN_PROGRESS is a special case where the bind operation
        is not yet completed, and we should not consider it a successful bind.
        """
        result_code = event.responses[-1]["result_code"]
        sasl_bind_in_progress = result_code == LDAPCodes.SASL_BIND_IN_PROGRESS

        return not sasl_bind_in_progress

    def _is_match_object_class(
        self,
        trigger: AuditPolicyTrigger,
        event: RawEvent,
    ) -> bool:
        """Check if event object class matches trigger object class."""
        return (
            trigger.object_class
            in event.context["before_attrs"]["objectclass"]
        )

    def _is_match_ldap_oid(
        self,
        trigger: AuditPolicyTrigger,
        event: RawEvent,
    ) -> bool:
        """Check if event OID matches trigger OID."""
        if trigger.additional_info is None:
            raise ValueError(
                "Extended operation trigger must have additional_info",
            )

        if "oid" not in trigger.additional_info:
            raise ValueError(
                "Trigger must have additional_info with 'oid'",
            )

        return trigger.additional_info["oid"] == event.request["request_name"]

    def is_match_trigger(
        self,
        trigger: AuditPolicyTrigger,
        event: RawEvent,
    ) -> bool:
        """Determine if event matches trigger conditions."""
        if event.request_code == OperationEvent.CHANGE_PASSWORD:
            return True

        if event.protocol == "API" and event.request_code in [
            OperationEvent.BIND,
            OperationEvent.AFTER_2FA,
            OperationEvent.KERBEROS_AUTH,
            OperationEvent.CHANGE_PASSWORD_KERBEROS,
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
                return self._is_match_object_class(trigger, event)

            elif event.request_code == OperationEvent.EXTENDED:
                return self._is_match_ldap_oid(trigger, event)

            return trigger.additional_info is None

        else:
            raise ValueError("Unsupported event")

    async def get_event_by_data(
        self,
        event_data: RawEvent,
        session: AsyncSession,
    ) -> list[AuditPolicyTrigger]:
        """Find all policy triggers matching event data."""
        is_ldap = event_data.protocol == "TCP_LDAP"
        is_http = "API" in event_data.protocol

        operation_code = event_data.request_code
        matched_triggers: list[AuditPolicyTrigger] = []

        triggers = await session.scalars(
            select(AuditPolicyTrigger)
            .join(AuditPolicyTrigger.audit_policy)
            .where(
                AuditPolicy.is_enabled.is_(True),
                AuditPolicyTrigger.operation_code == operation_code,
                AuditPolicyTrigger.is_operation_success.is_(
                    event_data.is_event_successful,
                ),
                or_(
                    AuditPolicyTrigger.is_ldap.is_(is_ldap),
                    AuditPolicyTrigger.is_http.is_(is_http),
                ),
            )
            .options(selectinload(AuditPolicyTrigger.audit_policy)),
        )  # fmt: skip

        logger.debug(
            f"Suitable triggers: {[trigger.id for trigger in triggers]}",
        )

        for trigger in triggers:
            if self.is_match_trigger(trigger, event_data):
                logger.debug(f"Matched policy: {trigger.audit_policy.name}")
                matched_triggers.append(trigger)

        return matched_triggers

    async def save_events(
        self,
        events: list[NormalizedEvent],
        redis_client: AuditNormalizedAdapter,
    ) -> None:
        """Persist normalized events to stream."""
        for event in events:
            await redis_client.send_event(event)

    async def handle_event(
        self,
        event: RawEvent,
        session: AsyncSession,
        raw_adapter: AuditRawAdapter,
        normalized_adapter: AuditNormalizedAdapter,
        _class: type[NormalizedEvent],
    ) -> None:
        """Process single event through entire pipeline."""
        logger.debug(f"Event data: {event}")
        try:
            events = await self.get_event_by_data(event, session)

            if not events:
                return

            normalize_events: list[NormalizedEvent] = [
                AuditEventNormalizer(event, policy, _class).build()
                for policy in events
            ]

            logger.debug(
                f"Normalized events: {[event for event in normalize_events]}",
            )

            await self.save_events(normalize_events, normalized_adapter)
        finally:
            await raw_adapter.delete_event(event.id)

    async def consume_events(self) -> None:
        """Consume events and process them."""
        raw_audit_adapter: AuditRawAdapter = await self.container.get(
            AuditRawAdapter,
        )
        await raw_audit_adapter.setup_reading()

        while True:
            try:
                async with self.container(scope=Scope.REQUEST) as container:
                    for event in await raw_audit_adapter.read_events():
                        kwargs = await resolve_deps(
                            func=self.handle_event,
                            container=container,
                        )
                        asyncio.gather(
                            self.handle_event(
                                event,
                                **kwargs,
                            ),
                        )
            except ConnectionError:
                await asyncio.sleep(1)
            except Exception as exc:
                logger.exception(f"Error reading stream: {exc}")

    async def run(self) -> None:
        """Start event handler main processing loop."""
        try:
            await self.consume_events()
        finally:
            await self.container.close()
