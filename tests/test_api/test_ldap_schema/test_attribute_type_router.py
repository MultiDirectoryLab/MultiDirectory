"""Test the attribute type router."""

import pytest
from fastapi import status
from httpx import AsyncClient

from api.ldap_schema.schema import AttributeTypeSchema

from .test_attribute_type_router_datasets import (
    test_delete_bulk_attribute_types_dataset,
    test_modify_one_attribute_type_dataset,
)


@pytest.mark.asyncio
async def test_get_one_extended_attribute_type(
    http_client: AsyncClient,
) -> None:
    """Test getting a single extended attribute type."""
    response = await http_client.get("/schema/attribute_type/objectClass")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, dict)
    assert data.get("object_class_names") == ["top"]


@pytest.mark.asyncio
async def test_create_one_attribute_type(
    http_client: AsyncClient,
) -> None:
    """Test creating a single attribute type."""
    schema = AttributeTypeSchema[None](
        oid="1.2.3.4",
        name="testAttribute",
        syntax="1.3.6.1.4.1.1466.115.121.1.15",
        single_value=True,
        no_user_modification=False,
        is_system=False,
        is_included_anr=False,
    )
    response = await http_client.post(
        "/schema/attribute_type",
        json=schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get(f"/schema/attribute_type/{schema.name}")
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)


@pytest.mark.asyncio
async def test_create_attribute_type_conflict_when_already_exists(
    http_client: AsyncClient,
) -> None:
    """Test that creating a duplicate attribute type returns a 409 Conflict."""
    schema = AttributeTypeSchema(
        oid="1.2.3.4",
        name="testAttribute",
        syntax="1.3.6.1.4.1.1466.115.121.1.15",
        single_value=True,
        no_user_modification=False,
        is_system=False,
        is_included_anr=False,
    )
    response = await http_client.post(
        "/schema/attribute_type",
        json=schema.model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/attribute_type",
        json=schema.model_dump(),
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_get_list_attribute_types_with_pagination(
    http_client: AsyncClient,
) -> None:
    """Test retrieving a list of attribute types."""
    page_number = 1
    page_size = 50
    response = await http_client.get(
        f"/schema/attribute_types?page_number={page_number}&page_size={page_size}",
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)
    assert len(response.json().get("items")) == page_size


@pytest.mark.asyncio
async def test_modify_one_attribute_type_raise_404(
    http_client: AsyncClient,
) -> None:
    """Test modifying a single attribute type (not exist)."""
    schema = AttributeTypeSchema(
        oid="1.2.3.4",
        name="testAttributeType1",
        syntax="1.3.6.1.4.1.1466.115.121.1.15",
        single_value=True,
        no_user_modification=False,
        is_system=False,
        is_included_anr=False,
    )

    response = await http_client.patch(
        "/schema/attribute_type/testAttributeType12345",
        json=schema.model_dump(),
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.parametrize(
    "dataset",
    test_modify_one_attribute_type_dataset,
)
@pytest.mark.asyncio
async def test_modify_one_attribute_type(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test modifying a single attribute type."""
    attribute_type_name = dataset["attribute_type_name"]

    response = await http_client.post(
        "/schema/attribute_type",
        json=dataset["attribute_type_schema"].model_dump(),
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.patch(
        f"/schema/attribute_type/{attribute_type_name}",
        json=dataset["attribute_type_changes"],
    )
    assert response.status_code == dataset["status_code"]

    if dataset["status_code"] == status.HTTP_200_OK:
        response = await http_client.get(
            f"/schema/attribute_type/{attribute_type_name}",
        )
        attribute_type_json = response.json()
        for field_name, value in dataset["attribute_type_changes"].items():
            assert attribute_type_json.get(field_name) == value


@pytest.mark.parametrize(
    "dataset",
    test_delete_bulk_attribute_types_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_bulk_attribute_types(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test deleting multiple attribute types."""
    attribute_type_schema: AttributeTypeSchema
    for attribute_type_schema in dataset["attribute_type_schemas"]:
        response = await http_client.post(
            "/schema/attribute_type",
            json=attribute_type_schema.model_dump(),
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/attribute_types/delete",
        json={"attribute_types_names": dataset["attribute_types_deleted"]},
    )
    assert response.status_code == dataset["status_code"]

    if dataset["status_code"] == status.HTTP_200_OK:
        for attribute_type_name in dataset["attribute_types_deleted"]:
            response = await http_client.get(
                f"/schema/attribute_type/{attribute_type_name}",
            )
            assert response.status_code == status.HTTP_400_BAD_REQUEST
