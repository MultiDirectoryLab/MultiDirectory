"""Test API Delete.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from httpx import AsyncClient

from ldap_protocol.ldap_codes import LDAPCodes


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_correct_delete(http_client: AsyncClient) -> None:
    """Test API for delete object."""
    response = await http_client.request(
        "delete",
        "/entry/delete",
        json={"entry": "cn=test,dc=md,dc=test"},
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_delete_with_incorrect_dn(http_client: AsyncClient) -> None:
    """Test API for delete object with incorrect DN."""
    response = await http_client.request(
        "delete",
        "/entry/delete",
        json={
            "entry": "cn!=test,dc=md,dc=test",
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_delete_non_exist_object(http_client: AsyncClient) -> None:
    """Test API for delete non-existen object."""
    response = await http_client.request(
        "delete",
        "/entry/delete",
        json={
            "entry": "cn=non-exist-object,dc=md,dc=test",
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.NO_SUCH_OBJECT


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_delete_many(http_client: AsyncClient) -> None:
    """Test API for bulk delete objects."""
    entry_dn_1 = "cn=test,dc=md,dc=test"
    entry_dn_2 = "cn=test2,dc=md,dc=test"
    entry_dn_3 = "cn=test3,dc=md,dc=test"

    response = await http_client.post(
        "/entry/add",
        json={
            "entry": entry_dn_2,
            "password": None,
            "attributes": [
                {"type": "name", "vals": ["test2"]},
                {"type": "cn", "vals": ["test2"]},
                {"type": "testing_attr", "vals": ["test2"]},
                {
                    "type": "objectClass",
                    "vals": ["organization", "top", "user"],
                },
            ],
        },
    )
    data = response.json()
    assert data["resultCode"] == LDAPCodes.SUCCESS

    response = await http_client.post(
        "/entry/add",
        json={
            "entry": entry_dn_3,
            "password": None,
            "attributes": [
                {"type": "name", "vals": ["test3"]},
                {"type": "cn", "vals": ["test3"]},
                {"type": "testing_attr", "vals": ["test3"]},
                {
                    "type": "objectClass",
                    "vals": ["organization", "top", "user"],
                },
            ],
        },
    )
    data = response.json()
    assert data["resultCode"] == LDAPCodes.SUCCESS

    response = await http_client.post(
        "/entry/delete_many",
        json=[
            {"entry": entry_dn_1},
            {"entry": entry_dn_2},
            {"entry": entry_dn_3},
        ],
    )

    data = response.json()

    assert all(
        [result.get("resultCode") == LDAPCodes.SUCCESS for result in data]
    )
