"""Test Password Policy RestAPI.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from unittest.mock import Mock

import pytest
from fastapi import status
from httpx import AsyncClient

from api.password_policy.schemas import PasswordPolicySchema


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
async def test_create(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test create one Password Policy endpoint."""
    password_policy_schema = PasswordPolicySchema[None, int](
        priority=1,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )  # fmt: skip
    response = await http_client.post(
        "/password-policy",
        json=password_policy_schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED
    password_use_cases.create.assert_called_once()


@pytest.mark.asyncio
async def test_create_without_priority(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test create one Password Policy without priority endpoint."""
    password_policy_schema = PasswordPolicySchema[None, None](
        priority=None,
        name="Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )  # fmt: skip
    response = await http_client.post(
        "/password-policy",
        json=password_policy_schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED
    password_use_cases.create.assert_called_once()


@pytest.mark.asyncio
async def test_get_policy_by_dir_path(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test get Password Policy by directory path endpoint."""
    path = "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test"
    response = await http_client.get(f"/password-policy/by_dir_path/{path}")
    assert response.status_code == status.HTTP_200_OK
    password_use_cases.get_password_policy_by_dir_path.assert_called_once()


@pytest.mark.asyncio
async def test_update(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test update one Password Policy endpoint."""
    schema = PasswordPolicySchema[int, int](
        id=1,
        priority=2,
        name="NOT Test Password Policy",
        group_paths=[],
        password_history_length=5,
        maximum_password_age_days=90,
        minimum_password_age_days=1,
        minimum_password_length=8,
        password_must_meet_complexity_requirements=True,
    )  # fmt: skip
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
