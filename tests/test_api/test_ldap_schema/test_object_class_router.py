"""Tests."""

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import ObjectClass

from .test_object_class_router_datasets import (
    test_create_one_object_class_dataset,
    test_delete_bulk_object_classes_dataset,
)


@pytest.mark.parametrize(
    "dataset",
    test_create_one_object_class_dataset,
)
@pytest.mark.asyncio
async def test_create_one_object_class(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test creating a single object class."""
    response = await http_client.post("/object_class", json=dataset)
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

    query = await session.scalars(select(ObjectClass))
    result = list(query.all())
    assert len(result) == len(response.json())


@pytest.mark.asyncio
async def test_modify_one_object_class(
    http_client: AsyncClient,
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
        query = await session.scalars(
            select(ObjectClass)
            .where(ObjectClass.name.in_(dataset["object_classes_deleted"])),
        )  # fmt: skip
        result = list(query.all())
        assert len(result) == 0
