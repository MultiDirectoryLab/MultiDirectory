"""Event Handler.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import operator
from typing import Callable

from loguru import logger
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.objects import OperationEvent
from models import AuditPolicy, AuditPolicyTrigger

from .dataclasses import NormalizedAuditEvent, RawAuditEvent
from .managers import NormalizedAuditManager, RawAuditManager
from .normalizer import AuditEventNormalizer

_OPERATIONS: dict[str, Callable] = {
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
        raw_audit_manager: RawAuditManager,
        normalized_audit_manager: NormalizedAuditManager,
        session: AsyncSession,
        normalized_class: type[NormalizedAuditEvent],
    ) -> None:
        """Initialize event handler."""
        self.raw_audit_manager = raw_audit_manager
        self.normalized_audit_manager = normalized_audit_manager
        self.session = session
        self.normalized_class = normalized_class

    def _check_modify_event(
        self,
        trigger: AuditPolicyTrigger,
        event: RawAuditEvent,
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
        op = _OPERATIONS[operation]
        result = trigger.additional_info["result"]

        return bool(op(first_value, second_value)) == result

    def _check_bind_event(self, event: RawAuditEvent) -> bool:
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
        event: RawAuditEvent,
    ) -> bool:
        """Check if event object class matches trigger object class."""
        return (
            trigger.object_class
            in event.context["before_attrs"]["objectclass"]
        )

    def _is_match_ldap_oid(
        self,
        trigger: AuditPolicyTrigger,
        event: RawAuditEvent,
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
        event: RawAuditEvent,
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
        event_data: RawAuditEvent,
    ) -> list[AuditPolicyTrigger]:
        """Find all policy triggers matching event data."""
        is_ldap = event_data.protocol == "TCP_LDAP"
        is_http = "API" in event_data.protocol

        operation_code = event_data.request_code
        matched_triggers: list[AuditPolicyTrigger] = []

        triggers = await self.session.scalars(
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
        )

        logger.debug(
            f"Suitable triggers: {[trigger.id for trigger in triggers]}",
        )

        for trigger in triggers:
            if self.is_match_trigger(trigger, event_data):
                logger.debug(f"Matched policy: {trigger.audit_policy.name}")
                matched_triggers.append(trigger)

        return matched_triggers

    async def save_events(self, events: list[NormalizedAuditEvent]) -> None:
        """Persist normalized events to stream."""
        for event in events:
            await self.normalized_audit_manager.send_event(event)

    async def handle_event(self, event: RawAuditEvent) -> None:
        """Process single event through entire pipeline."""
        logger.debug(f"Event data: {event}")
        try:
            events = await self.get_event_by_data(event)

            if not events:
                return

            normalize_events: list[NormalizedAuditEvent] = [
                AuditEventNormalizer(
                    event,
                    policy,
                    self.normalized_class,
                ).build()
                for policy in events
            ]

            logger.debug(
                f"Normalized events: {[event for event in normalize_events]}",
            )

            await self.save_events(normalize_events)
        finally:
            await self.raw_audit_manager.delete_event(event.id)  # type: ignore

    async def run(self) -> None:
        """Start event handler main processing loop."""
        await self.raw_audit_manager.setup_reading()

        while True:
            try:
                for event in await self.raw_audit_manager.read_events():
                    asyncio.gather(
                        self.handle_event(event),
                    )
            except ConnectionError:
                await asyncio.sleep(1)
            except Exception as exc:
                logger.exception(f"Error reading stream: {exc}")
