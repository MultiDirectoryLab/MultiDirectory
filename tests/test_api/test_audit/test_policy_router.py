"""Test audit policy API.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from fastapi import status
from httpx import AsyncClient

from ldap_protocol.policies.audit.schemas import AuditPolicySchemaRequest


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_update_audit_policy(http_client: AsyncClient) -> None:
    """Test updating an audit policy."""
    response = await http_client.get("/audit/policies")
    assert response.status_code == status.HTTP_200_OK
    policies = response.json()

    assert policies, "There should be at least one audit policy"

    policy_id = policies[0]["id"]
    new_policy_id = 999999
    model = AuditPolicySchemaRequest(
        id=new_policy_id,
        name="Test Policy",
        is_enabled=True,
        severity="high",
    )

    response = await http_client.put(
        f"/audit/policy/{policy_id}",
        json=model.model_dump(),
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == model.id
    assert data["name"] == model.name
    assert data["is_enabled"] == model.is_enabled

    response = await http_client.get("/audit/policies")
    assert response.status_code == status.HTTP_200_OK

    policies = response.json()

    update_policy = next(
        (
            AuditPolicySchemaRequest(**p)
            for p in policies
            if p["id"] == new_policy_id
        ),
        None,
    )
    assert update_policy

    assert update_policy.id == model.id
    assert update_policy.name == model.name
    assert update_policy.is_enabled == model.is_enabled
