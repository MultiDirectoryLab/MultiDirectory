"""Test the access policy router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_list_access_policies_with_pagination(
    http_client: AsyncClient,
) -> None:
    """Test retrieving a list of access policies."""
    page_size = 1
    response = await http_client.get(f"/access_policy/1?page_size={page_size}")
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)
    assert len(response.json().get("items")) == page_size
