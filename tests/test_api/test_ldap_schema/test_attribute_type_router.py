"""Test the attribute type routers."""

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_schema.attribute_type_crud import (
    get_attribute_type_by_name,
    get_attribute_types_by_names,
)
from models import AttributeType

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
        "syntax": "testSyntax",
        "single_value": True,
        "no_user_modification": False,
        "is_system": False,
    }
    response = await http_client.post("/attribute_type", json=request_data)
    assert response.status_code == status.HTTP_201_CREATED


@pytest.mark.asyncio
async def test_get_list_attribute_types(
    http_client: AsyncClient,
) -> None:
    """Test retrieving a list of attribute types."""
    response = await http_client.get("/attribute_type")
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_modify_one_attribute_type_raise_404(
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test modifying a single attribute type."""
    attribute_type_data = {
        "oid": "1.2.3.4",
        "name": "testAttributeType1",
        "syntax": "testSyntax",
        "single_value": True,
        "no_user_modification": False,
        "is_system": False,
    }
    session.add(AttributeType(**attribute_type_data))
    await session.commit()

    response = await http_client.patch(
        "/attribute_type/testAttributeType12345",
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
    session: AsyncSession,
) -> None:
    """Test modifying a single attribute type."""
    attribute_type_name = dataset["attribute_type_name"]

    session.add(AttributeType(**dataset["attribute_type_data"]))
    await session.commit()

    response = await http_client.patch(
        f"/attribute_type/{attribute_type_name}",
        json=dataset["attribute_type_changes"],
    )
    assert response.status_code == dataset["status_code"]

    if dataset["status_code"] == status.HTTP_200_OK:
        attribute_type = await get_attribute_type_by_name(
            attribute_type_name,
            session,
        )
        for field_name, value in dataset["attribute_type_changes"].items():
            assert getattr(attribute_type, field_name) == value


@pytest.mark.parametrize(
    "dataset",
    test_delete_bulk_attribute_types_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_bulk_attribute_types(
    dataset: dict,
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test deleting multiple attribute types."""
    for attribute_type_data in dataset["attribute_type_datas"]:
        session.add(AttributeType(**attribute_type_data))
        await session.commit()

    response = await http_client.post(
        "/attribute_type/delete",
        json={"attribute_types_names": dataset["attribute_types_deleted"]},
    )
    assert response.status_code == dataset["status_code"]

    if dataset["status_code"] == status.HTTP_200_OK:
        result = await get_attribute_types_by_names(
            dataset["attribute_types_deleted"],
            session,
        )
        assert len(result) == 0
