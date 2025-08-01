"""Audit policies schemas module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from pydantic import BaseModel, Field

from .enums import AuditDestinationProtocolType, AuditDestinationServiceType


class AuditPolicySchemaRequest(BaseModel):
    """Audit policy schema request."""

    id: int
    name: str
    is_enabled: bool
    severity: str


@dataclass
class AuditPolicySchema:
    """Audit policy schema."""

    id: int
    name: str
    is_enabled: bool
    severity: str


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


@dataclass
class AuditDestinationSchema:
    """Audit destination schema."""

    id: int
    name: str
    service_type: str
    is_enabled: bool
    host: str
    port: int
    protocol: str
