"""Test User Password History router.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from unittest.mock import Mock

import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_clear_success(
    http_client: AsyncClient,
    user_password_history_use_cases: Mock,
) -> None:
    """Test clear user password history endpoint."""
    user_name = "testuser"
    response = await http_client.post(
        f"/user/password_history/clear/{user_name}",
    )

    # NOTE to user_password_history_use_cases.reset returned Mock, not wrapper  # noqa: E501
    user_password_history_use_cases._perm_checker = None  # noqa: SLF001
    user_password_history_use_cases.clear.assert_called_once()
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_clear_unauthorized(
    http_client_with_login_perm: AsyncClient,
    user_password_history_use_cases: Mock,
) -> None:
    """Test clear user password history endpoint without permissions."""
    user_name = "testuser"
    response = await http_client_with_login_perm.post(
        f"/user/password_history/clear/{user_name}",
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    # NOTE to user_password_history_use_cases.reset returned Mock, not wrapper  # noqa: E501
    user_password_history_use_cases._perm_checker = None  # noqa: SLF001
    user_password_history_use_cases.clear.assert_not_called()
