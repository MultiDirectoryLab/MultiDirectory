"""Test Password Policy RestAPI.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from unittest.mock import Mock

import pytest
from fastapi import status
from httpx import AsyncClient

from api.password_policy.schemas import PasswordPolicySchema

from .datasets import test_update_data


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
async def test_get_password_policy_by_dir_path_dn(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test get Password Policy by directory path endpoint."""
    path = "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test"
    response = await http_client.get(
        f"/password-policy/by_dir_path_dn/{path}",
    )
    assert response.status_code == status.HTTP_200_OK
    password_use_cases.get_password_policy_by_dir_path_dn.assert_called_once()


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
async def test_turnoff(
    http_client: AsyncClient,
    password_use_cases: Mock,
) -> None:
    """Test turnoff one Password Policy endpoint."""
    response = await http_client.put("/password-policy/turnoff/1")
    assert response.status_code == status.HTTP_200_OK
    password_use_cases.turnoff.assert_called_once_with(1)
