"""Tests."""

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_one_object_class(
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test creating a single object class."""
    request_data = {
        "oid": "1.2.3.4",
        "name": "testObjectClass",
        "superior": "testSuperior",
        "kind": "STRUCTURAL",
        "is_system": False,
        "attribute_types_must": [],
        "attribute_types_may": [],
    }
    response = await http_client.post("/object_class", json=request_data)
    assert response.status_code == status.HTTP_201_CREATED


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_get_list_object_classes(
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test retrieving a list of object classes."""
    response = await http_client.get("/object_class")
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_modify_one_object_class(
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test modifying a single object class."""
    object_class_name = "organizationalPerson"
    request_data = {
        "oid": "1.2.3.4",
        "name": "modifiedObjectClass",
        "superior": "top",
        "kind": "STRUCTURAL",
        "is_system": True,
        "attribute_types_must": [],
        "attribute_types_may": [],
    }
    response = await http_client.patch(
        f"/object_class/{object_class_name}",
        json=request_data,
    )
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_bulk_object_classes(
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test deleting multiple object classes."""
    object_classes_names = ["testObjectClass1", "testObjectClass2"]
    response = await http_client.post(
        "/object_class/delete",
        json={"object_classes_names": object_classes_names},
    )
    assert response.status_code == status.HTTP_200_OK
