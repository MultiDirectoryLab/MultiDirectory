"""Audit policies router.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Depends, status

from api.auth import get_current_user
from ldap_protocol.policies.audit.dataclasses import (
    AuditDestinationDTO,
    AuditPolicyDTO,
)
from ldap_protocol.policies.audit.schemas import (
    AuditDestinationSchemaRequest,
    AuditPolicySchemaRequest,
)

from .adapter import AuditPoliciesAdapter

audit_router = APIRouter(
    prefix="/audit",
    tags=["Audit policy"],
    dependencies=[Depends(get_current_user)],
    route_class=DishkaRoute,
)


@audit_router.get("/policies")
async def get_audit_policies(
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> list[AuditPolicyDTO]:
    """Get all audit policies."""
    return await audit_adapter.get_policies()


@audit_router.put("/policy/{policy_id}")
async def update_audit_policy(
    policy_id: int,
    policy_data: AuditPolicySchemaRequest,
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> None:
    """Update an existing audit policy."""
    return await audit_adapter.update_policy(policy_id, policy_data)


@audit_router.get("/destinations")
async def get_audit_destinations(
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> list[AuditDestinationDTO]:
    """Get all audit destinations."""
    return await audit_adapter.get_destinations()


@audit_router.post("/destination", status_code=status.HTTP_201_CREATED)
async def create_audit_destination(
    destination_data: AuditDestinationSchemaRequest,
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> None:
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
) -> None:
    """Update an existing audit destination."""
    return await audit_adapter.update_destination(
        destination_id,
        destination_data,
    )
