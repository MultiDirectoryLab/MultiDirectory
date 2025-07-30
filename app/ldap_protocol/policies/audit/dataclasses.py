"""Audit log data classes.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from ldap_protocol.objects import OperationEvent

from .enums import AuditSeverity


@dataclass
class AuditPolicyDTO:
    """Audit policy data transfer object."""

    object_class: str
    action: str
    is_success: bool
    severity: AuditSeverity
    is_enabled: bool = False

    @property
    def name(self) -> str:
        """Return the name of the audit policy."""
        status = "ok" if self.is_success else "fail"
        return f"{self.action}_{self.object_class}_{status}"

    @property
    def as_db_dict(self) -> dict:
        """Convert the data transfer object to a dictionary."""
        return {
            "name": self.name,
            "is_enabled": self.is_enabled,
            "severity": self.severity,
        }


@dataclass
class AuditPolicyTriggerDTO:
    """Audit policy trigger data transfer object."""

    is_ldap: bool
    is_http: bool
    operation_code: OperationEvent
    object_class: str
    operation_success: bool
    additional_info: dict | None = None
