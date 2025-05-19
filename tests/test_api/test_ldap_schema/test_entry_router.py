"""Tests the entry router."""

import pytest
from fastapi import status
from httpx import AsyncClient

from .test_entry_router_datasets import (
    test_create_one_entry_dataset,
    test_delete_bulk_entries_dataset,
    test_get_list_entries_with_pagination_dataset,
    test_modify_one_entry_dataset,
)


@pytest.mark.parametrize(
    "dataset",
    test_create_one_entry_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_one_entry(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test creating a single entry."""
    for object_class_data in dataset["object_classes"]:
        response = await http_client.post(
            "/schema/object_class",
            json=object_class_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/entry",
        json=dataset["entry"],
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.get(
        f"/schema/entry/{dataset['entry']['name']}",
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)


@pytest.mark.parametrize(
    "dataset",
    test_get_list_entries_with_pagination_dataset,
)
@pytest.mark.asyncio
async def test_get_list_entries_with_pagination(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test retrieving a list of entries."""
    for entry_data in dataset["entries"]:
        response = await http_client.post(
            "/schema/entry",
            json=entry_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    page_size = 2
    response = await http_client.get(
        f"/schema/entries/1?page_size={page_size}"
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)
    assert len(response.json().get("items")) == page_size


@pytest.mark.parametrize(
    "dataset",
    test_modify_one_entry_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_modify_one_entry(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test modifying a single entry."""
    for object_class_data in dataset["object_classes"]:
        response = await http_client.post(
            "/schema/object_class",
            json=object_class_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/entry",
        json=dataset["entry"],
    )
    assert response.status_code == status.HTTP_201_CREATED

    new_statement = dataset["new_statement"]
    response = await http_client.patch(
        f"/schema/entry/{dataset['entry']['name']}",
        json=new_statement,
    )
    assert response.status_code == status.HTTP_200_OK

    response = await http_client.get(
        f"/schema/entry/{dataset['new_statement']['name']}",
    )
    assert response.status_code == status.HTTP_200_OK
    assert isinstance(response.json(), dict)
    entry = response.json()
    assert set(entry.get("name")) == set(new_statement.get("name"))  # type: ignore
    assert set(entry.get("object_class_names")) == set(
        new_statement.get("object_class_names")
    )  # type: ignore


@pytest.mark.parametrize(
    "dataset",
    test_delete_bulk_entries_dataset,
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_delete_bulk_entries(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test deleting multiple entries."""
    for entry_data in dataset["entry_datas"]:
        response = await http_client.post(
            "/schema/entry",
            json=entry_data,
        )
        assert response.status_code == status.HTTP_201_CREATED

    response = await http_client.post(
        "/schema/entry/delete",
        json={"entry_names": dataset["entries_deleted"]},
    )
    assert response.status_code == status.HTTP_200_OK

    for entry_name in dataset["entries_deleted"]:
        response = await http_client.get(
            f"/schema/entry/{entry_name}",
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
