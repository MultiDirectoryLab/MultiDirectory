"""Test API Modify.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from httpx import AsyncClient

from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_requests.modify import Operation


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_correct_modify(http_client: AsyncClient) -> None:
    """Test API for modify object attribute."""
    entry_dn = "cn=test,dc=md,dc=test"
    new_value = "133632677730000000"
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": entry_dn,
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "accountExpires",
                        "vals": [new_value],
                    },
                },
            ],
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": entry_dn,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": [],
            "page_number": 1,
        },
    )

    data = response.json()

    assert data["resultCode"] == LDAPCodes.SUCCESS
    assert data["search_result"][0]["object_name"] == entry_dn

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "accountExpires":
            assert attr["vals"][0] == new_value


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_modify_many(http_client: AsyncClient) -> None:
    """Test API for modify object attribute."""
    entry_dn = "cn=test,dc=md,dc=test"
    new_value = "133632677730000000"
    response = await http_client.patch(
        "/entry/update_many",
        json=[
            {
                "object": entry_dn,
                "changes": [
                    {
                        "operation": Operation.REPLACE,
                        "modification": {
                            "type": "accountExpires",
                            "vals": [new_value],
                        },
                    },
                ],
            },
            {
                "object": entry_dn,
                "changes": [
                    {
                        "operation": Operation.REPLACE,
                        "modification": {
                            "type": "testing_attr",
                            "vals": ["test1"],
                        },
                    },
                ],
            },
        ],
    )

    data = response.json()

    assert isinstance(data, list)
    for result in data:
        assert result.get("resultCode") == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": entry_dn,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": [],
            "page_number": 1,
        },
    )

    data = response.json()

    assert data["resultCode"] == LDAPCodes.SUCCESS
    assert data["search_result"][0]["object_name"] == entry_dn

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "accountExpires":
            assert attr["vals"][0] == new_value
        if attr["type"] == "testing_attr":
            assert attr["vals"][0] == "test1"


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_modify_with_incorrect_dn(http_client: AsyncClient) -> None:
    """Test API for modify object attribute with incorrect DN."""
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": "cn!=test,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "name",
                        "vals": ["new_test"],
                    },
                },
            ],
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_modify_non_exist_object(http_client: AsyncClient) -> None:
    """Test API for modify object attribute with non-existen attribute."""
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": "cn=test,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "name",
                        "vals": ["new_test"],
                    },
                },
            ],
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.NO_SUCH_OBJECT


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_correct_modify_replace_memberof(
    http_client: AsyncClient,
) -> None:
    """Test API for modify object attribute."""
    user = "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test"
    new_group = "cn=domain admins,cn=groups,dc=md,dc=test"
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": user,
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "memberOf",
                        "vals": [new_group],
                    },
                },
            ],
        },
    )
    data = response.json()

    assert data["resultCode"] == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": user,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": [],
            "page_number": 1,
        },
    )

    data = response.json()

    assert user == data["search_result"][0]["object_name"]

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "memberOf":
            assert attr["vals"] == [new_group]
            break
    else:
        raise Exception("No groups")


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_modify_add_loop_detect_member(
    http_client: AsyncClient,
) -> None:
    """Test API for modify object attribute."""
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": "cn=developers,cn=groups,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.ADD,
                    "modification": {
                        "type": "member",
                        "vals": ["cn=user0,ou=users,dc=md,dc=test"],
                    },
                },
            ],
        },
    )
    data = response.json()

    assert data["resultCode"] == LDAPCodes.LOOP_DETECT


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_modify_add_loop_detect_memberof(
    http_client: AsyncClient,
) -> None:
    """Test API for modify object attribute."""
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": "cn=user0,ou=users,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.ADD,
                    "modification": {
                        "type": "memberOf",
                        "vals": ["cn=developers,cn=groups,dc=md,dc=test"],
                    },
                },
            ],
        },
    )
    data = response.json()

    assert data["resultCode"] == LDAPCodes.LOOP_DETECT


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_modify_replace_loop_detect_member(
    http_client: AsyncClient,
) -> None:
    """Test API for modify object attribute."""
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": "cn=developers,cn=groups,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "member",
                        "vals": [
                            "cn=user0,ou=users,dc=md,dc=test",
                            "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test",  # noqa
                        ],
                    },
                },
            ],
        },
    )
    data = response.json()

    assert data["resultCode"] == LDAPCodes.LOOP_DETECT


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_modify_replace_loop_detect_memberof(
    http_client: AsyncClient,
) -> None:
    """Test API for modify object attribute."""
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": "cn=user0,ou=users,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "memberOf",
                        "vals": [
                            "cn=developers,cn=groups,dc=md,dc=test",
                            "cn=domain admins,cn=groups,dc=md,dc=test",
                        ],
                    },
                },
            ],
        },
    )
    data = response.json()

    assert data["resultCode"] == LDAPCodes.LOOP_DETECT


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("session")
async def test_api_modify_incorrect_uac(http_client: AsyncClient) -> None:
    """Test API for modify object attribute."""
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": "cn=user0,ou=users,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "userAccountControl",
                        "vals": ["string"],
                    },
                },
            ],
        },
    )
    data = response.json()

    assert data["resultCode"] == LDAPCodes.UNDEFINED_ATTRIBUTE_TYPE
