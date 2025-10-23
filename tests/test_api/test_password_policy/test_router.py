"""Test Password Policy RestAPI.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from unittest.mock import Mock

import pytest
from fastapi import status
from httpx import AsyncClient

from api.password_policy.schemas import PasswordPolicySchema

from .datasets import (
    test_create_data,
    test_create_without_priority_data,
    test_update_data,
)


@pytest.mark.asyncio
async def test_get_all(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test get all Password Policy endpoint."""
    response = await http_client.get("/password-policy/all")
    assert response.status_code == status.HTTP_200_OK

    password_use_cases.get_all.assert_called_once()


@pytest.mark.asyncio
async def test_get(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test get one Password Policy endpoint."""
    response = await http_client.get("/password-policy/1")
    assert response.status_code == status.HTTP_200_OK
    password_use_cases.get.assert_called_once_with(1)


@pytest.mark.asyncio
@pytest.mark.parametrize("schema", test_create_data)
async def test_create(
    schema: PasswordPolicySchema[None, int],
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test create one Password Policy endpoint."""
    response = await http_client.post(
        "/password-policy",
        json=schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED
    password_use_cases.create.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("schema", test_create_without_priority_data)
async def test_create_without_priority(
    schema: PasswordPolicySchema[None, None],
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test create one Password Policy without priority endpoint."""
    response = await http_client.post(
        "/password-policy",
        json=schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED
    password_use_cases.create.assert_called_once()


@pytest.mark.asyncio
async def test_get_password_policy_by_dir_path(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test get Password Policy by directory path endpoint."""
    path = "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test"
    response = await http_client.get(f"/password-policy/by_dir_path/{path}")
    assert response.status_code == status.HTTP_200_OK
    password_use_cases.get_password_policy_by_dir_path.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("schema", test_update_data)
async def test_update(
    schema: PasswordPolicySchema[int, int],
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test update one Password Policy endpoint."""
    response = await http_client.put(
        "/password-policy/1",
        json=schema.model_dump(),
    )
    assert response.status_code == status.HTTP_200_OK
    password_use_cases.update.assert_called_once()


@pytest.mark.asyncio
async def test_delete(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test delete one Password Policy endpoint."""
    response = await http_client.delete("/password-policy/1")
    assert response.status_code == status.HTTP_200_OK
    password_use_cases.delete.assert_called_once()


@pytest.mark.asyncio
async def test_reset_domain_policy_to_default_config(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test reset domain Password Policy to default config endpoint."""
    response = await http_client.put(
        "/password-policy/reset/domain_policy_to_default_config",
    )
    assert response.status_code == status.HTTP_200_OK
    password_use_cases.reset_domain_policy_to_default_config.assert_called_once()


@pytest.mark.asyncio
async def test_update_priorities(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test update priorities of all password policies endpoint."""
    response = await http_client.put(
        "/password-policy/update/priorities",
        json={},
    )
    assert response.status_code == status.HTTP_200_OK
    password_use_cases.update_priorities.assert_called_once()


@pytest.mark.asyncio
async def test_turnoff(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test turnoff one Password Policy endpoint."""
    response = await http_client.put("/password-policy/turnoff/1")
    assert response.status_code == status.HTTP_200_OK
    password_use_cases.turnoff.assert_called_once_with(1)
