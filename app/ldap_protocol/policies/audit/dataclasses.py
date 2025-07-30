"""Audit log data classes.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from .enums import AuditSeverity


@dataclass
class AuditPolicyDTO:
    """Audit policy data transfer object."""

    name: str
    is_enabled: bool
    severity: AuditSeverity


@dataclass
class AuditPolicyTriggerDTO:
    """Audit policy trigger data transfer object."""

    is_ldap: bool
    is_http: bool
    operation_code: int
    object_class: str
    additional_info: dict
    operation_success: bool
