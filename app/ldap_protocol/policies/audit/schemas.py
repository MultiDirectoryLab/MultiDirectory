"""Audit policies schemas module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel, Field, field_serializer

from models import (
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
    AuditSeverity,
)


class _AuditPolicySchema(BaseModel):
    """Base schema for audit policies."""

    id: int
    name: str
    is_enabled: bool


class AuditPolicySchemaRequest(_AuditPolicySchema):
    """Audit policy schema request."""

    severity: str


class AuditPolicySchema(_AuditPolicySchema):
    """Audit policy schema."""

    severity: AuditSeverity

    @field_serializer("severity")
    def serialize_severity(self, severity: AuditSeverity) -> str:
        return severity.name.lower()


class AuditDestinationSchemaRequest(BaseModel):
    """Audit destination request schema."""

    name: str
    service_type: AuditDestinationServiceType
    is_enabled: bool
    host: str = Field(..., description="IPv4, IPv6 or FQDN")
    port: int
    protocol: AuditDestinationProtocolType

    class Config:  # noqa: D106
        use_enum_values = True


class AuditDestinationSchema(AuditDestinationSchemaRequest):
    """Audit destination schema."""

    id: int
