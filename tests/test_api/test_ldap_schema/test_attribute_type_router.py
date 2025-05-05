"""Test the attribute type router."""

import pytest
from fastapi import status
from httpx import AsyncClient

from .test_attribute_type_router_datasets import (
    test_delete_bulk_attribute_types_dataset,
    test_modify_one_attribute_type_dataset,
)


@pytest.mark.asyncio
async def test_create_one_attribute_type(
    http_client: AsyncClient,
) -> None:
    """Test creating a single attribute type."""
    request_data = {
        "oid": "1.2.3.4",
        "name": "testAttribute",
        "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
        "single_value": True,
        "no_user_modification": False,
        "is_system": False,
    }
    response = await http_client.post(
        "/schema/attribute_type",
        json=request_data,
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get(
        f"/schema/attribute_type/{request_data['name']}",
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)


@pytest.mark.asyncio
async def test_get_list_attribute_types_with_pagination(
    http_client: AsyncClient,
) -> None:
    """Test retrieving a list of attribute types."""
    page_size = 50
    response = await http_client.get(
        f"/schema/attribute_types/1?page_size={page_size}"
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)
    assert len(response.json().get("items")) == page_size


@pytest.mark.asyncio
async def test_modify_one_attribute_type_raise_404(
    http_client: AsyncClient,
) -> None:
    """Test modifying a single attribute type (not exist)."""
    attribute_type_data = {
        "oid": "1.2.3.4",
        "name": "testAttributeType1",
        "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
        "single_value": True,
        "no_user_modification": False,
        "is_system": False,
    }

    response = await http_client.patch(
        "/schema/attribute_type/testAttributeType12345",
        json=attribute_type_data,
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


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
        json=dataset["attribute_type_data"],
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
    for attribute_type_data in dataset["attribute_type_datas"]:
        response = await http_client.post(
            "/schema/attribute_type",
            json=attribute_type_data,
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
            assert response.status_code == status.HTTP_404_NOT_FOUND
