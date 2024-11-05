"""Test policy API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from copy import copy

import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_policy_password(http_client: AsyncClient) -> None:
    """Test create policy."""
    policy_data = {
        "name": "Default domain password policy",
        "password_history_length": 4,
        "maximum_password_age_days": 0,
        "minimum_password_age_days": 0,
        "minimum_password_length": 7,
        "password_must_meet_complexity_requirements": True,
    }

    response = await http_client.post("/password-policy", json=policy_data)

    assert response.status_code == 201
    assert response.json() == policy_data

    response = await http_client.get("/password-policy")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == policy_data

    changed_data = copy(policy_data)
    changed_data['maximum_password_age_days'] = 80
    changed_data['minimum_password_age_days'] = 30

    response = await http_client.put(
        "/password-policy",
        json=changed_data,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == changed_data

    response = await http_client.get("/password-policy")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == changed_data

    response = await http_client.delete("/password-policy")

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == policy_data

    response = await http_client.get("/password-policy")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == policy_data
