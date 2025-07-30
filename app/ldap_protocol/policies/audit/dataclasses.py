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

    name: str
    severity: AuditSeverity
    is_enabled: bool = False


@dataclass
class AuditPolicyTriggerDTO:
    """Audit policy trigger data transfer object."""

    is_ldap: bool
    is_http: bool
    operation_code: OperationEvent
    object_class: str
    operation_success: bool
    additional_info: dict | None = None
