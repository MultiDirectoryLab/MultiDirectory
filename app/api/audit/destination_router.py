"""Audit destinations router.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka

from api.audit import audit_router
from ldap_protocol.policies.audit.schemas import (
    AuditDestinationSchema,
    AuditDestinationSchemaRequest,
)

from .adapter import AuditPoliciesAdapter


@audit_router.get("/destinations")
async def get_audit_destinations(
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> list[AuditDestinationSchema]:
    """Get all audit destinations."""
    return await audit_adapter.get_destinations()


@audit_router.post("/destination")
async def create_audit_destination(
    destination_data: AuditDestinationSchemaRequest,
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> AuditDestinationSchema:
    """Create a new audit destination."""
    return await audit_adapter.create_destination(destination_data)


@audit_router.delete("/destination/{destination_id}")
async def delete_audit_destination(
    destination_id: int,
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> None:
    """Delete an audit destination."""
    await audit_adapter.delete_destination(destination_id)


@audit_router.put("/destination/{destination_id}")
async def update_audit_destination(
    destination_id: int,
    destination_data: AuditDestinationSchemaRequest,
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> AuditDestinationSchema:
    """Update an existing audit destination."""
    return await audit_adapter.update_destination(
        destination_id,
        destination_data,
    )
