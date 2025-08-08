"""Normalize audit events.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_protocol.objects import OperationEvent
from models import AuditPolicyTrigger

from .dataclasses import NormalizedAuditEvent, RawAuditEvent


class AuditEventNormalizer:
    """Interactor for normalizing audit events."""

    event_data: RawAuditEvent
    trigger: AuditPolicyTrigger

    def __init__(
        self,
        event_data: RawAuditEvent,
        trigger: AuditPolicyTrigger,
        _class: type[NormalizedAuditEvent],
    ) -> None:
        """Initialize normalizer with event data and trigger."""
        self.event_data = event_data
        self.trigger = trigger
        self._class = _class

    def _enrich_ldap_details(self, details: dict) -> None:
        """Add LDAP-specific details to event details.

        This method enriches the details dictionary with information
        specific to LDAP operations, such as target DN and group differences.
        It handles modify operations by checking the change attributes
        and calculating differences in group memberships.

        Example:
            details = {
                "target_dn": "cn=example,dc=domain,dc=com",
                "diff_groups": ["cn=group1,dc=domain,dc=com"],
            }

        """
        if self.event_data.request_code == OperationEvent.MODIFY:
            details["target_dn"] = self.event_data.request["object"]

            if not self.trigger.additional_info:
                raise ValueError(
                    "Modify operation trigger must have additional_info",
                )

            if not self.trigger.additional_info["change_attributes"]:
                return

            change_attribute = self.trigger.additional_info[
                "change_attributes"
            ][0]
            if change_attribute in {"member", "memberof"}:
                first_value = set(
                    self.event_data.context["before_attrs"][change_attribute],
                )
                second_value = set(
                    self.event_data.context["after_attrs"][change_attribute],
                )
                if not first_value - second_value:
                    details["diff_groups"] = list(second_value - first_value)
                else:
                    details["diff_groups"] = list(first_value - second_value)
        elif self.event_data.request_code != OperationEvent.BIND:
            details["target_dn"] = self.event_data.request["entry"]

    def _prepare_details(self) -> dict:
        """Prepare base details structure from event data."""
        details = self.event_data.context.get("details", {})

        if "LDAP" in self.event_data.protocol:
            self._enrich_ldap_details(details)

        return details

    def _extract_error_info(self) -> dict[str, str]:
        """Extract error information from failed event."""
        if "error_code" in self.event_data.context.get("details", {}):
            details = self.event_data.context["details"]
            return {
                "error_code": details["error_code"],
                "error_message": details["error_message"],
            }
        elif self.event_data.protocol.endswith("LDAP"):
            last_response = self.event_data.responses[-1]
            return {
                "error_code": last_response["result_code"],
                "error_message": last_response["error_message"],
            }
        return {}

    def build(self) -> NormalizedAuditEvent:
        """Normalize event data и вернуть pydantic-модель."""
        details = self._prepare_details()
        if not self.trigger.is_operation_success:
            details.update(self._extract_error_info())

        protocol = "API" if "API" in self.event_data.protocol else "LDAP"
        if self.trigger.operation_code in {
            OperationEvent.KERBEROS_AUTH,
            OperationEvent.CHANGE_PASSWORD_KERBEROS,
        }:
            protocol = "KERBEROS"

        return self._class(
            username=self.event_data.username,
            source_ip=str(self.event_data.source_ip),
            dest_port=self.event_data.dest_port,
            timestamp=self.event_data.timestamp,
            hostname=self.event_data.hostname,
            protocol=protocol,
            event_type=self.trigger.audit_policy.name,
            severity=str(self.trigger.audit_policy.severity),
            policy_id=self.trigger.audit_policy.id,
            is_operation_success=self.trigger.is_operation_success,
            service_name=self.event_data.service_name,
            details=details,
        )
