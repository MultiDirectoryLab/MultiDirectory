"""Tests the entity type router."""

import pytest
from fastapi import status
from httpx import AsyncClient

from .test_entity_type_router_datasets import (
    test_create_one_entity_type_dataset,
    test_delete_bulk_entity_types_dataset,
    test_get_list_entity_types_with_pagination_dataset,
    test_modify_one_entity_type_dataset,
)


@pytest.mark.parametrize(
    "dataset",
    test_create_one_entity_type_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_one_entity_type(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test creating a single entity type."""
    for object_class_data in dataset["object_classes"]:
        response = await http_client.post(
            "/schema/object_class",
            json=object_class_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/entity_type",
        json=dataset["entity_type"],
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get(
        f"/schema/entity_type/{dataset['entity_type']['name']}",
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_one_entity_type_value_400(
    http_client: AsyncClient,
) -> None:
    """Test bad request error while creating a single entity type."""
    response = await http_client.post(
        "/schema/entity_type",
        json={
            "name": "testEntityType1",
            "object_class_names": ["testObjectClass1"],
            "is_system": False,
        },
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_one_entity_type_value_422(
    http_client: AsyncClient,
) -> None:
    """Test bad request error while creating a single entity type."""
    response = await http_client.post(
        "/schema/entity_type",
        json={
            "name": "testEntityType1",
            "object_class_names": [],
            "is_system": False,
        },
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.parametrize(
    "dataset",
    test_get_list_entity_types_with_pagination_dataset,
)
@pytest.mark.asyncio
async def test_get_list_entity_types_with_pagination(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test retrieving a list of entity types."""
    for oid, object_class_name in dataset["object_class_names"]:
        response = await http_client.post(
            "/schema/object_class",
            json={
                "oid": oid,
                "name": object_class_name,
                "superior_name": None,
                "kind": "STRUCTURAL",
                "is_system": False,
                "attribute_type_names_must": [],
                "attribute_type_names_may": [],
            },
        )
        assert response.status_code == status.HTTP_201_CREATED

    for entity_type_data in dataset["entity_types"]:
        response = await http_client.post(
            "/schema/entity_type",
            json=entity_type_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    page_number = 1
    page_size = 2
    response = await http_client.get(
        f"/schema/entity_types?page_number={page_number}&page_size={page_size}",
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)
    assert len(response.json().get("items")) == page_size


@pytest.mark.parametrize(
    "dataset",
    test_modify_one_entity_type_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_modify_one_entity_type(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test modifying a single entity type."""
    for object_class_data in dataset["object_classes"]:
        response = await http_client.post(
            "/schema/object_class",
            json=object_class_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/entity_type",
        json=dataset["entity_type"],
    )
    assert response.status_code == status.HTTP_201_CREATED

    new_statement = dataset["new_statement"]
    response = await http_client.patch(
        f"/schema/entity_type/{dataset['entity_type']['name']}",
        json=new_statement,
    )
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get(
        f"/schema/entity_type/{dataset['new_statement']['name']}",
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)
    entity_type = response.json()
    assert set(entity_type.get("name")) == set(new_statement.get("name"))
    assert set(entity_type.get("object_class_names")) == set(
        new_statement.get("object_class_names"),
    )


@pytest.mark.parametrize(
    "dataset",
    test_delete_bulk_entity_types_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_bulk_entries(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test deleting multiple entries."""
    for object_class_data in dataset["object_classes"]:
        response = await http_client.post(
            "/schema/object_class",
            json=object_class_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    for entity_type_data in dataset["entity_types"]:
        response = await http_client.post(
            "/schema/entity_type",
            json=entity_type_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/entity_type/delete",
        json={"entity_type_names": dataset["entity_type_names_deleted"]},
    )
    assert response.status_code == status.HTTP_200_OK

    for entity_type_name in dataset["entity_type_names_deleted"]:
        response = await http_client.get(
            f"/schema/entity_type/{entity_type_name}",
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_entry_with_directory(http_client: AsyncClient) -> None:
    """Test deleting entry with directory."""
    entity_type_name = "User"
    response = await http_client.post(
        "/schema/entity_type/delete",
        json={"entity_type_names": [entity_type_name]},
    )
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get(
        f"/schema/entity_type/{entity_type_name}",
    )
    assert response.status_code == status.HTTP_200_OK
