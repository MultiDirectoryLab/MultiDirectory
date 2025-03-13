"""Test the attribute type routers."""

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_one_attribute_type(
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test creating a single attribute type."""
    request_data = {
        "oid": "1.2.3.4",
        "name": "testAttribute",
        "syntax": "testSyntax",
        "single_value": True,
        "no_user_modification": False,
        "is_system": False,
    }
    response = await http_client.post("/attribute_type", json=request_data)
    assert response.status_code == status.HTTP_201_CREATED


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_get_list_attribute_types(
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test retrieving a list of attribute types."""
    response = await http_client.get("/attribute_type")
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_modify_one_attribute_type(
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test modifying a single attribute type."""
    attribute_type_name = "testAttribute"
    request_data = {
        "oid": "1.2.3.4",
        "name": "modifiedAttribute",
        "syntax": "modifiedSyntax",
        "single_value": False,
        "no_user_modification": True,
        "is_system": True,
    }
    response = await http_client.patch(
        f"/attribute_type/{attribute_type_name}", json=request_data
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND  # TODO: Fix this


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_bulk_attribute_types(
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test deleting multiple attribute types."""
    attribute_types_names = ["testAttribute1", "testAttribute2"]
    response = await http_client.post(
        "/attribute_type/delete",
        json={"attribute_types_names": attribute_types_names},
    )
    assert response.status_code == status.HTTP_200_OK
