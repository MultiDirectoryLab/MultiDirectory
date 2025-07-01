"""Tests the object class router."""

import pytest
from fastapi import status
from httpx import AsyncClient

from ldap_protocol.ldap_schema.object_class_dao import ObjectClassUpdateSchema

from .test_object_class_router_datasets import (
    test_create_one_object_class_dataset,
    test_delete_bulk_object_classes_dataset,
    test_delete_bulk_used_object_classes_dataset,
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


@pytest.mark.parametrize(
    "dataset",
    test_create_one_object_class_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_object_class_type_conflict_when_already_exists(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test that creating a duplicate object class type returns a 409."""
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

    response = await http_client.post(
        "/schema/object_class",
        json=dataset["object_class"],
    )
    assert response.status_code == status.HTTP_409_CONFLICT


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_modify_system_object_class(http_client: AsyncClient) -> None:
    """Test modify system object_class."""
    page_number = 1
    page_size = 10
    response = await http_client.get(
        f"/schema/object_classes?page_number={page_number}&page_size={page_size}"
    )
    for object_class in response.json()["items"]:
        if object_class["is_system"] is True:
            object_class_name = object_class["name"]
            request_data = ObjectClassUpdateSchema.model_validate(object_class)
            response = await http_client.patch(
                f"/schema/object_class/{object_class_name}",
                json=request_data.model_dump(),
            )
            assert response.status_code == status.HTTP_403_FORBIDDEN
            break
    else:
        pytest.fail("No system object class")


@pytest.mark.asyncio
async def test_get_list_object_classes_with_pagination(
    http_client: AsyncClient,
) -> None:
    """Test retrieving a list of object classes."""
    page_number = 1
    page_size = 25
    response = await http_client.get(
        f"/schema/object_classes?page_number={page_number}&page_size={page_size}"
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
    )
    assert set(object_class.get("attribute_type_names_may")) == set(
        new_statement.get("attribute_type_names_may")
    )


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
        "/schema/object_class/delete",
        json={"object_classes_names": dataset["object_classes_deleted"]},
    )
    assert response.status_code == dataset["status_code"]

    if dataset["status_code"] == status.HTTP_200_OK:
        for object_class_name in dataset["object_classes_deleted"]:
            response = await http_client.get(
                f"/schema/object_class/{object_class_name}",
            )
            assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.parametrize(
    "dataset",
    test_delete_bulk_used_object_classes_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_bulk_used_object_classes(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test of removing object classes during use."""
    response = await http_client.post(
        "/schema/object_class",
        json=dataset["object_class_data"],
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/entity_type",
        json=dataset["entity_type_data"],
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/object_class/delete",
        json={"object_classes_names": [dataset["object_class_deleted"]]},
    )
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get(
        f"/schema/object_class/{dataset['object_class_deleted']}",
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json().get("name") == dataset["object_class_deleted"]
