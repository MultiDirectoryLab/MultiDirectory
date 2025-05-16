"""Test the OpenAPI router."""

import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_swagger_ui(
    http_client: AsyncClient,
) -> None:
    """Test the Swagger UI."""
    response = await http_client.get("/api/docs")
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_redoc(
    http_client: AsyncClient,
) -> None:
    """Test the ReDoc."""
    response = await http_client.get("/api/redoc")
    assert response.status_code == status.HTTP_200_OK
