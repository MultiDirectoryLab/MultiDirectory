"""Audit policies router.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from fastapi import Depends, status
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from api.auth.utils import verify_auth
from enums import ProjectPartCodes
from errors import (
    ERROR_MAP_TYPE,
    BaseErrorTranslator,
    DishkaErrorAwareRoute,
    ErrorStatusCodes,
)
from ldap_protocol.policies.audit.exception import (
    AuditAlreadyExistsError,
    AuditNotFoundError,
)
from ldap_protocol.policies.audit.schemas import (
    AuditDestinationResponse,
    AuditDestinationSchemaRequest,
    AuditPolicyResponse,
    AuditPolicySchemaRequest,
)

from .adapter import AuditPoliciesAdapter


class AuditErrorTranslator(BaseErrorTranslator):
    """Audit error translator."""

    domain_code = ProjectPartCodes.AUDIT


error_map: ERROR_MAP_TYPE = {
    AuditNotFoundError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=AuditErrorTranslator(),
    ),
    AuditAlreadyExistsError: rule(
        status=ErrorStatusCodes.BAD_REQUEST,
        translator=AuditErrorTranslator(),
    ),
}

audit_router = ErrorAwareRouter(
    prefix="/audit",
    tags=["Audit policy"],
    dependencies=[Depends(verify_auth)],
    route_class=DishkaErrorAwareRoute,
)


@audit_router.get("/policies", error_map=error_map)
async def get_audit_policies(
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> list[AuditPolicyResponse]:
    """Get all audit policies."""
    return await audit_adapter.get_policies()


@audit_router.put("/policy/{policy_id}", error_map=error_map)
async def update_audit_policy(
    policy_id: int,
    policy_data: AuditPolicySchemaRequest,
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> None:
    """Update an existing audit policy."""
    return await audit_adapter.update_policy(policy_id, policy_data)


@audit_router.get("/destinations", error_map=error_map)
async def get_audit_destinations(
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> list[AuditDestinationResponse]:
    """Get all audit destinations."""
    return await audit_adapter.get_destinations()


@audit_router.post(
    "/destination",
    status_code=status.HTTP_201_CREATED,
    error_map=error_map,
)
async def create_audit_destination(
    destination_data: AuditDestinationSchemaRequest,
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> None:
    """Create a new audit destination."""
    return await audit_adapter.create_destination(destination_data)


@audit_router.delete("/destination/{destination_id}", error_map=error_map)
async def delete_audit_destination(
    destination_id: int,
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> None:
    """Delete an audit destination."""
    await audit_adapter.delete_destination(destination_id)


@audit_router.put("/destination/{destination_id}", error_map=error_map)
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
