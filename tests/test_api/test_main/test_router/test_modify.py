"""Test API Modify.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

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
async def test_api_duplicate_with_spaces_modify(
    http_client: AsyncClient,
) -> None:
    """Test API for modify duplicated object name."""
    entry_dn = "cn=new_test,dc=md,dc=test"
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": entry_dn,
            "password": None,
            "attributes": [
                {
                    "type": "objectClass",
                    "vals": ["organization", "top"],
                },
            ],
        },
    )
    data = response.json()
    assert data.get("resultCode") == LDAPCodes.SUCCESS

    response = await http_client.patch(
        "/entry/update",
        json={
            "object": entry_dn,
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "cn",
                        "vals": ["  test"],
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
    assert isinstance(data, dict)
    assert data["search_result"][0]["object_name"] == entry_dn


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
            "attributes": ["testing_attr", "accountExpires"],
            "page_number": 1,
        },
    )

    data = response.json()

    assert data["resultCode"] == LDAPCodes.SUCCESS
    assert data["search_result"][0]["object_name"] == entry_dn

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "accountExpires":
            assert attr["vals"] == [new_value]
        if attr["type"] == "testing_attr":
            assert attr["vals"] == ["test1"]


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
    user = "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test"
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
                        "vals": ["cn=user0,cn=users,dc=md,dc=test"],
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
            "object": "cn=user0,cn=users,dc=md,dc=test",
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
                            "cn=user0,cn=users,dc=md,dc=test",
                            "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test",
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
            "object": "cn=user0,cn=users,dc=md,dc=test",
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
            "object": "cn=user0,cn=users,dc=md,dc=test",
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


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_qpi_modify_primary_object_classes(
    http_client: AsyncClient,
) -> None:
    """Test deleting primary object class."""
    entry_dn = "cn=user0,cn=users,dc=md,dc=test"
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": entry_dn,
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "objectClass",
                        "vals": [],
                    },
                },
            ],
        },
    )
    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.OPERATIONS_ERROR


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_set_primary_group(
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test API for setting primary group."""
    user_dn = "cn=test,dc=md,dc=test"
    group_dn = "cn=domain admins,cn=groups,dc=md,dc=test"

    response = await http_client.post(
        "/entry/set_primary_group",
        json={
            "directory_dn": user_dn,
            "group_dn": group_dn,
        },
    )

    assert response.status_code == 200

    session.expire_all()

    response = await http_client.post(
        "/entry/search",
        json={
            "base_object": user_dn,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["primaryGroupID", "memberOf"],
            "page_number": 1,
        },
    )

    data = response.json()
    assert data["resultCode"] == LDAPCodes.SUCCESS
    assert data["search_result"][0]["object_name"] == user_dn

    primary_group_id = None
    member_of = []
    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "primaryGroupID":
            primary_group_id = attr["vals"][0]
        if attr["type"] == "memberOf":
            member_of = attr["vals"]

    assert primary_group_id is not None
    assert group_dn in member_of
