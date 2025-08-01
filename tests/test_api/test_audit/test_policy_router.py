"""Test audit policy API.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from unittest.mock import Mock

import pytest
from fastapi import status
from httpx import AsyncClient

from ldap_protocol.policies.audit.dataclasses import AuditPolicyDTO
from ldap_protocol.policies.audit.schemas import AuditPolicySchemaRequest


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_update_audit_policy(
    http_client: AsyncClient,
    audit_service: Mock,
) -> None:
    """Test updating an audit policy."""
    policy_id = 1
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
    old_policy_id, policy_dto = audit_service.update_policy.call_args.args
    assert old_policy_id == policy_id
    assert policy_dto == AuditPolicyDTO(**model.model_dump())
