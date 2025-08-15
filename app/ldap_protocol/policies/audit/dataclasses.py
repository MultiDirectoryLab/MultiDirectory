"""Audit log data classes.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass, field

from enums import (
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
    AuditSeverity,
)
from ldap_protocol.objects import OperationEvent


@dataclass
class AuditPolicyTriggerDTO:
    """Audit policy trigger data transfer object."""

    is_ldap: bool
    is_http: bool
    operation_code: OperationEvent
    object_class: str
    is_operation_success: bool
    additional_info: dict | None = None


@dataclass
class AuditDestinationDTO:
    """Audit destination data transfer object."""

    name: str
    service_type: AuditDestinationServiceType
    is_enabled: bool
    host: str
    port: int
    protocol: AuditDestinationProtocolType
    id: int | None = None

    def get_id(self) -> int:
        """Get the ID of the audit destination."""
        if not self.id:
            raise ValueError("ID is not set for the audit destination.")
        return self.id


@dataclass
class AuditPolicyDTO:
    """Audit policy data transfer object."""

    name: str
    severity: AuditSeverity
    is_enabled: bool = False
    id: int | None = field(default=None, compare=False)

    def get_id(self) -> int:
        """Get the ID of the audit policy."""
        if not self.id:
            raise ValueError("ID is not set for the audit policy.")
        return self.id


@dataclass
class AuditPolicySetupDTO(AuditPolicyDTO):
    """Audit policy data transfer object."""

    triggers: list[AuditPolicyTriggerDTO] = field(default_factory=list)

    @staticmethod
    def create_name(
        is_success: bool,
        action: str,
        object_class: str,
    ) -> str:
        """Return the name of the audit policy."""
        status = "ok" if is_success else "fail"
        return f"{action}_{object_class}_{status}"

    def as_dict(self) -> dict:
        """Convert the data transfer object to a dictionary."""
        return {
            "name": self.name,
            "is_enabled": self.is_enabled,
            "severity": self.severity,
        }
