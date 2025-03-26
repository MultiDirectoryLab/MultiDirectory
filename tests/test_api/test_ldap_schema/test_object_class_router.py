"""Tests."""

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_schema.object_class_crud import (
    create_object_class,
    get_object_class_by_name,
    get_object_classes_by_names,
)
from models import AttributeType, ObjectClass

from .test_object_class_router_datasets import (
    test_create_one_object_class_dataset,
    test_delete_bulk_object_classes_dataset,
    test_modify_one_object_class_dataset,
)


@pytest.mark.parametrize(
    "dataset",
    test_create_one_object_class_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_one_object_class(
    dataset: dict,
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test creating a single object class."""
    for attribute_type_data in dataset["attribute_types"]:
        session.add(AttributeType(**attribute_type_data))
        await session.commit()

    response = await http_client.post(
        "/object_class",
        json=dataset["object_class"],
    )
    assert response.status_code == status.HTTP_201_CREATED


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_get_list_object_classes(
    http_client: AsyncClient,
) -> None:
    """Test retrieving a list of object classes."""
    response = await http_client.get("/object_class")
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), list)


@pytest.mark.parametrize(
    "dataset",
    test_modify_one_object_class_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_modify_one_object_class(
    dataset: dict,
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test modifying a single object class."""
    for attribute_type_data in dataset["attribute_types"]:
        session.add(AttributeType(**attribute_type_data))
        await session.commit()
    await create_object_class(**dataset["object_class_data"], session=session)

    new_statement = dataset["new_statement"]
    response = await http_client.patch(
        f"/object_class/{dataset['object_class_data']['name']}",
        json=new_statement,
    )
    assert response.status_code == status.HTTP_200_OK

    object_class = await get_object_class_by_name(
        str(dataset["object_class_data"].get("name", "")),
        session,
    )
    assert isinstance(object_class, ObjectClass)
    assert object_class.superior == new_statement.get("superior")
    assert object_class.kind == new_statement.get("kind")
    assert object_class.is_system == new_statement.get("is_system")
    assert set(object_class.attribute_types_must_display) == set(
        new_statement.get("attribute_types_must", [])
    )  # type: ignore
    assert set(object_class.attribute_types_may_display) == set(
        new_statement.get("attribute_types_may", [])
    )  # type: ignore


@pytest.mark.parametrize(
    "dataset",
    test_delete_bulk_object_classes_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_bulk_object_classes(
    dataset: dict,
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test deleting multiple object classes."""
    for object_class_data in dataset["object_class_datas"]:
        session.add(ObjectClass(**object_class_data))
        await session.commit()

    response = await http_client.post(
        "/object_class/delete",
        json={"object_classes_names": dataset["object_classes_deleted"]},
    )
    assert response.status_code == dataset["status_code"]

    if dataset["status_code"] == status.HTTP_200_OK:
        object_classes = await get_object_classes_by_names(
            dataset["object_classes_deleted"],
            session,
        )
        assert len(object_classes) == 0
