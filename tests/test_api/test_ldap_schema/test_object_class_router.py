"""Tests the object class router."""

import pytest
from fastapi import status
from httpx import AsyncClient

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
) -> None:
    """Test creating a single object class."""
    for attribute_type_data in dataset["attribute_types"]:
        response = await http_client.post(
            "/schema/attribute_type",
            json=attribute_type_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/object_class",
        json=dataset["object_class"],
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get(
        f"/schema/object_class/{dataset['object_class']['name']}",
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)


@pytest.mark.asyncio
async def test_get_list_object_classes_with_pagination(
    http_client: AsyncClient,
) -> None:
    """Test retrieving a list of object classes."""
    page_size = 25
    response = await http_client.get(
        f"/schema/object_classes/1?page_size={page_size}"
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)
    assert len(response.json().get("items")) == page_size


@pytest.mark.parametrize(
    "dataset",
    test_modify_one_object_class_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_modify_one_object_class(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test modifying a single object class."""
    for attribute_type_data in dataset["attribute_types"]:
        response = await http_client.post(
            "/schema/attribute_type",
            json=attribute_type_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/object_class",
        json=dataset["object_class_data"],
    )
    assert response.status_code == status.HTTP_201_CREATED

    new_statement = dataset["new_statement"]
    response = await http_client.patch(
        f"/schema/object_class/{dataset['object_class_data']['name']}",
        json=new_statement,
    )
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get(
        f"/schema/object_class/{dataset['object_class_data']['name']}",
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)
    object_class = response.json()
    assert set(object_class.get("attribute_type_names_must")) == set(
        new_statement.get("attribute_type_names_must")
    )  # type: ignore
    assert set(object_class.get("attribute_type_names_may")) == set(
        new_statement.get("attribute_type_names_may")
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
) -> None:
    """Test deleting multiple object classes."""
    for object_class_data in dataset["object_class_datas"]:
        response = await http_client.post(
            "/schema/object_class",
            json=object_class_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/object_classes/delete",
        json={"object_classes_names": dataset["object_classes_deleted"]},
    )
    assert response.status_code == dataset["status_code"]

    if dataset["status_code"] == status.HTTP_200_OK:
        for object_class_name in dataset["object_classes_deleted"]:
            response = await http_client.get(
                f"/schema/object_class/{object_class_name}",
            )
            assert response.status_code == status.HTTP_404_NOT_FOUND
