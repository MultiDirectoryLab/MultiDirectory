"""Audit policies router.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka

from api.audit import audit_router
from ldap_protocol.policies.audit.schemas import (
    AuditPolicySchema,
    AuditPolicySchemaRequest,
)

from .adapter import AuditPoliciesAdapter


@audit_router.get("/policies")
async def get_audit_policies(
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> list[AuditPolicySchema]:
    """Get all audit policies."""
    return await audit_adapter.get_policies()


@audit_router.put("/policies/{policy_id}")
async def update_audit_policy(
    policy_id: int,
    policy_data: AuditPolicySchemaRequest,
    audit_adapter: FromDishka[AuditPoliciesAdapter],
) -> AuditPolicySchema:
    """Update an existing audit policy."""
    return await audit_adapter.update_policy(policy_id, policy_data)
