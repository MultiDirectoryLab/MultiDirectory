"""Tests the entity type router."""

import pytest
from fastapi import status
from httpx import AsyncClient

from api.ldap_schema.schema import AttributeTypeSchema, EntityTypeSchema
from constants import ENTITY_TYPE_DTOS_V1
from enums import EntityTypeNames

from .test_entity_type_router_datasets import (
    test_create_one_entity_type_dataset,
    test_delete_bulk_entity_types_dataset,
    test_get_list_entity_types_with_pagination_dataset,
    test_modify_entity_type_with_duplicates_dataset,
    test_modify_one_entity_type_dataset,
)


@pytest.mark.parametrize("dataset", test_create_one_entity_type_dataset)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_one_entity_type(dataset: dict, http_client: AsyncClient) -> None:
    """Test creating a single entity type."""
    for object_class_data in dataset["object_classes"]:
        response = await http_client.post("/schema/object_class", json=object_class_data)
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post("/schema/entity_type", json=dataset["entity_type"])
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get(f"/schema/entity_type/{dataset['entity_type']['name']}")
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_one_entity_type_value_400(http_client: AsyncClient) -> None:
    """Test bad request error while creating a single entity type."""
    response = await http_client.post(
        "/schema/entity_type",
        json={"name": "testEntityType1", "object_class_names": ["testObjectClass1"], "is_system": False},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_one_entity_type_value_422(http_client: AsyncClient) -> None:
    """Test bad request error while creating a single entity type."""
    response = await http_client.post(
        "/schema/entity_type", json={"name": "testEntityType1", "object_class_names": [], "is_system": False}
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.parametrize("dataset", test_get_list_entity_types_with_pagination_dataset)
@pytest.mark.asyncio
async def test_get_list_entity_types_with_pagination(dataset: dict, http_client: AsyncClient) -> None:
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
        response = await http_client.post("/schema/entity_type", json=entity_type_data)
        assert response.status_code == status.HTTP_201_CREATED

    page_number = 1
    page_size = 2
    response = await http_client.get(f"/schema/entity_types?page_number={page_number}&page_size={page_size}")
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)
    assert len(response.json().get("items")) == page_size


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_get_entity_type_attributes(http_client: AsyncClient) -> None:
    """Test retrieving attribute names for an entity type."""
    attribute_types = [
        AttributeTypeSchema(
            oid="1.2.3.100",
            name="testEntityTypeAttr1",
            ldap_display_name="testEntityTypeAttr1",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=True,
            no_user_modification=False,
            is_system=False,
            is_included_anr=False,
        ),
        AttributeTypeSchema(
            oid="1.2.3.101",
            name="testEntityTypeAttr2",
            ldap_display_name="testEntityTypeAttr2",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=True,
            no_user_modification=False,
            is_system=False,
            is_included_anr=False,
        ),
    ]
    for attribute_type in attribute_types:
        response = await http_client.post("/schema/attribute_type", json=attribute_type.model_dump())
        assert response.status_code == status.HTTP_201_CREATED

    object_class_name = "testEntityTypeObjectClass"
    response = await http_client.post(
        "/schema/object_class",
        json={
            "oid": "1.2.3.102",
            "name": object_class_name,
            "superior_name": None,
            "kind": "STRUCTURAL",
            "is_system": False,
            "attribute_type_names_must": ["testEntityTypeAttr1"],
            "attribute_type_names_may": ["testEntityTypeAttr2"],
        },
    )
    assert response.status_code == status.HTTP_201_CREATED

    entity_type_name = "testEntityTypeWithAttrs"
    response = await http_client.post(
        "/schema/entity_type",
        json=EntityTypeSchema(
            name=entity_type_name, object_class_names=[object_class_name], is_system=False
        ).model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get(f"/schema/entity_type/{entity_type_name}/attrs")
    assert response.status_code == status.HTTP_200_OK
    assert set(response.json()) == {"testEntityTypeAttr1", "testEntityTypeAttr2"}


@pytest.mark.parametrize("dataset", test_modify_entity_type_with_duplicates_dataset)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_modify_entity_type_with_duplicate_data(dataset: dict, http_client: AsyncClient) -> None:
    """Test modifying an entity type with duplicate data."""
    for object_class_data in dataset["object_classes"]:
        response = await http_client.post("/schema/object_class", json=object_class_data)
        assert response.status_code == status.HTTP_201_CREATED

    for entity_type in dataset["entity_types"]:
        response = await http_client.post("/schema/entity_type", json=entity_type)
        assert response.status_code == status.HTTP_201_CREATED

    new_statements = dataset["new_statements"]
    update_entity, update_data = new_statements["duplicate_object_class_names"]
    response = await http_client.patch(f"/schema/entity_type/{update_entity}", json=update_data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    update_entity, update_data = new_statements["duplicate_name"]
    response = await http_client.patch(f"/schema/entity_type/{update_entity}", json=update_data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.parametrize("dataset", test_modify_one_entity_type_dataset)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_modify_one_entity_type(dataset: dict, http_client: AsyncClient) -> None:
    """Test modifying a single entity type."""
    for object_class_data in dataset["object_classes"]:
        response = await http_client.post("/schema/object_class", json=object_class_data)
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post("/schema/entity_type", json=dataset["entity_type"])
    assert response.status_code == status.HTTP_201_CREATED

    new_statement = dataset["new_statement"]
    response = await http_client.patch(f"/schema/entity_type/{dataset['entity_type']['name']}", json=new_statement)
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get(f"/schema/entity_type/{dataset['new_statement']['name']}")
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)
    entity_type = response.json()
    assert set(entity_type.get("name")) == set(new_statement.get("name"))
    assert set(entity_type.get("object_class_names")) == set(new_statement.get("object_class_names"))


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_modify_primary_entity_type_name(http_client: AsyncClient) -> None:
    """Test modifying a primary entity type name."""
    new_statement = "TestEntityTypeName"
    entity_type_dto = ENTITY_TYPE_DTOS_V1[0]
    response = await http_client.patch(
        f"/schema/entity_type/{entity_type_dto.name}",
        json=EntityTypeSchema(
            name=new_statement,
            object_class_names=entity_type_dto.object_class_names,
            is_system=entity_type_dto.is_system,
        ).model_dump(),
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    response = await http_client.get(f"/schema/entity_type/{entity_type_dto.name}")
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)


@pytest.mark.parametrize("dataset", test_delete_bulk_entity_types_dataset)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_bulk_entries(dataset: dict, http_client: AsyncClient) -> None:
    """Test deleting multiple entries."""
    for object_class_data in dataset["object_classes"]:
        response = await http_client.post("/schema/object_class", json=object_class_data)
        assert response.status_code == status.HTTP_201_CREATED

    for entity_type_data in dataset["entity_types"]:
        response = await http_client.post("/schema/entity_type", json=entity_type_data)
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/entity_type/delete", json={"entity_type_names": dataset["entity_type_names_deleted"]}
    )
    assert response.status_code == status.HTTP_200_OK

    for entity_type_name in dataset["entity_type_names_deleted"]:
        response = await http_client.get(f"/schema/entity_type/{entity_type_name}")
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_entry_with_directory(http_client: AsyncClient) -> None:
    """Test deleting entry with directory."""
    entity_type_name = EntityTypeNames.USER
    response = await http_client.post("/schema/entity_type/delete", json={"entity_type_names": [entity_type_name]})
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get(f"/schema/entity_type/{entity_type_name}")
    assert response.status_code == status.HTTP_200_OK
