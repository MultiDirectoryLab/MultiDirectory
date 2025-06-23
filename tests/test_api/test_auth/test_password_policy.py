"""Test policy API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from copy import copy

import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_password_policy(http_client: AsyncClient) -> None:
    """Test create policy."""
    policy_data = {
        "name": "Default domain password policy",
        "history_length": 4,
        "min_age_days": 0,
        "max_age_days": 0,
        "min_length": 7,
        "max_length": 32,
        "min_lowercase_letters_count": 0,
        "min_uppercase_letters_count": 0,
        "min_letters_count": 0,
        "min_special_symbols_count": 0,
        "min_digits_count": 0,
        "min_unique_symbols_count": 0,
        "max_repeating_symbols_in_row_count": 0,
        "max_sequential_keyboard_symbols_count": 0,
        "max_sequential_alphabet_symbols_count": 0,
    }

    response = await http_client.post("/password-policy", json=policy_data)

    assert response.status_code == 201
    assert response.json() == policy_data

    response = await http_client.get("/password-policy")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == policy_data

    changed_data = copy(policy_data)
    changed_data["max_age_days"] = 80
    changed_data["min_age_days"] = 30

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
