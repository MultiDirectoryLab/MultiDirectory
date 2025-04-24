"""Test API Add.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from fastapi import status
from httpx import AsyncClient

from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.user_account_control import UserAccountControlFlag


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_correct_add(http_client: AsyncClient) -> None:
    """Test api correct add."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "password": None,
            "attributes": [
                {
                    "type": "name",
                    "vals": ["test"],
                },
                {
                    "type": "cn",
                    "vals": ["test"],
                },
                {
                    "type": "objectClass",
                    "vals": ["organization", "top"],
                },
                {
                    "type": "memberOf",
                    "vals": [
                        "cn=domain admins,cn=groups,dc=md,dc=test",
                    ],
                },
            ],
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert response.status_code == status.HTTP_200_OK
    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert data.get("errorMessage") == ""


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_add_computer(http_client: AsyncClient) -> None:
    """Test api correct add computer."""
    new_entry = "cn=PC,dc=md,dc=test"
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": new_entry,
            "password": None,
            "attributes": [
                {
                    "type": "name",
                    "vals": ["test"],
                },
                {
                    "type": "cn",
                    "vals": ["test"],
                },
                {
                    "type": "objectClass",
                    "vals": ["computer", "top"],
                },
            ],
        },
    )

    assert response.status_code == status.HTTP_200_OK

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": new_entry,
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

    assert data["search_result"][0]["object_name"] == new_entry

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "userAccountControl":
            assert (
                int(attr["vals"][0])
                & UserAccountControlFlag.WORKSTATION_TRUST_ACCOUNT
            )
            break
    else:
        raise Exception("Computer without userAccountControl")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_correct_add_double_member_of(
    http_client: AsyncClient,
) -> None:
    """Test api correct add a group with a register.

    assigning it to a user,
    and displaying it in the Search request.
    """
    new_group = "cn=Domain Admins,dc=md,dc=test"
    user = "cn=test0,dc=md,dc=test"
    un = "test0"
    groups = [
        "cn=domain admins,cn=groups,dc=md,dc=test",
        new_group,
    ]

    response = await http_client.post(
        "/entry/add",
        json={
            "entry": new_group,
            "password": None,
            "attributes": [
                {
                    "type": "objectClass",
                    "vals": ["top", "group"],
                },
                {
                    "type": "groupType",
                    "vals": ["-2147483646"],
                },
                {
                    "type": "instanceType",
                    "vals": ["4"],
                },
            ],
        },
    )
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert data.get("resultCode") == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": new_group,
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

    assert data["search_result"][0]["object_name"] == new_group

    for attr in data["search_result"][0]["partial_attributes"]:
        assert attr["type"] != "memberOf"

    response = await http_client.post(
        "/entry/add",
        json={
            "entry": user,
            "password": "P@ssw0rd",
            "attributes": [
                {
                    "type": "name",
                    "vals": [un],
                },
                {
                    "type": "cn",
                    "vals": [un],
                },
                {
                    "type": "objectClass",
                    "vals": ["organization", "top", "user"],
                },
                {
                    "type": "sAMAccountName",
                    "vals": [un],
                },
                {
                    "type": "userPrincipalName",
                    "vals": [f"{un}@md.ru"],
                },
                {
                    "type": "mail",
                    "vals": [f"{un}@md.ru"],
                },
                {
                    "type": "displayName",
                    "vals": [un],
                },
                {
                    "type": "memberOf",
                    "vals": groups,
                },
                {
                    "type": "userAccountControl",
                    "vals": ["514"],
                },
            ],
        },
    )
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert data.get("resultCode") == LDAPCodes.SUCCESS

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

    assert response.status_code == status.HTTP_200_OK
    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert data["search_result"][0]["object_name"] == user

    created_groups = groups + ["cn=domain users,cn=groups,dc=md,dc=test"]

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "memberOf":
            assert all(group in created_groups for group in attr["vals"])
            break
    else:
        raise Exception("memberOf not found")

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "userAccountControl":
            assert attr["vals"][0] == "514"
            break
    else:
        raise Exception("userAccountControl not found")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_add_user_inccorect_uac(http_client: AsyncClient) -> None:
    """Test api add."""
    user = "cn=test0,dc=md,dc=test"
    un = "test0"

    response = await http_client.post(
        "/entry/add",
        json={
            "entry": user,
            "password": "P@ssw0rd",
            "attributes": [
                {
                    "type": "name",
                    "vals": [un],
                },
                {
                    "type": "cn",
                    "vals": [un],
                },
                {
                    "type": "objectClass",
                    "vals": ["organization", "top", "user"],
                },
                {
                    "type": "sAMAccountName",
                    "vals": [un],
                },
                {
                    "type": "userPrincipalName",
                    "vals": [f"{un}@md.ru"],
                },
                {
                    "type": "mail",
                    "vals": [f"{un}@md.ru"],
                },
                {
                    "type": "displayName",
                    "vals": [un],
                },
                {
                    "type": "userAccountControl",
                    "vals": ["516"],
                },
            ],
        },
    )
    data = response.json()

    assert response.status_code == status.HTTP_200_OK
    assert data.get("resultCode") == LDAPCodes.SUCCESS

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

    assert response.status_code == status.HTTP_200_OK
    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert data["search_result"][0]["object_name"] == user

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "userAccountControl":
            assert attr["vals"][0] == "512"
            break
    else:
        raise Exception("userAccountControl not found")


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_add_non_auth_user(unbound_http_client: AsyncClient) -> None:
    """Test API add for unauthorized user."""
    unbound_http_client.cookies.set("id", "09e67421-2f92-8ddc-494108a6e04f")
    response = await unbound_http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
    )

    data = response.json()

    assert response.status_code == 401
    assert data.get("detail") == "Could not validate credentials"


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_add_with_incorrect_dn(http_client: AsyncClient) -> None:
    """Test API add a user with incorrect DN."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn!=test,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
    )

    data = response.json()
    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_add_with_incorrect_name(http_client: AsyncClient) -> None:
    """Test API add a user with incorrect name."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,test,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
    )

    data = response.json()
    assert data.get("resultCode") == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_add_with_space_end_name(http_client: AsyncClient) -> None:
    """Test API add a user with incorrect name."""
    entry = "cn=test test ,dc=md,dc=test"
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": entry,
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

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": entry,
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

    assert data["search_result"][0]["object_name"] == entry


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_add_with_non_exist_parent(http_client: AsyncClient) -> None:
    """Test API add a user with non-existen parent."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,ou=testing,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.NO_SUCH_OBJECT


# @pytest.mark.asyncio
# @pytest.mark.usefixtures("adding_test_user")
# @pytest.mark.usefixtures("setup_session")
# @pytest.mark.usefixtures("session")
# async def test_api_double_add(http_client: AsyncClient) -> None:
#     """Test API for adding a user who already exists."""
#     response = await http_client.post(
#         "/entry/add",
#         json={
#             "entry": "cn=test,dc=md,dc=test",
#             "password": None,
#             "attributes": [
#                 {
#                     "type": "name",
#                     "vals": ["test"],
#                 },
#                 {
#                     "type": "cn",
#                     "vals": ["test"],
#                 },
#                 {
#                     "type": "objectClass",
#                     "vals": ["organization", "top"],
#                 },
#                 {
#                     "type": "memberOf",
#                     "vals": [
#                         "cn=domain admins,cn=groups,dc=md,dc=test",
#                     ],
#                 },
#             ],
#         },
#     )

#     data = response.json()

#     assert isinstance(data, dict)
#     assert data.get("resultCode") == LDAPCodes.ENTRY_ALREADY_EXISTS


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_add_double_case_insensetive(
    http_client: AsyncClient,
) -> None:
    """Test api double add."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "attributes": [
                {
                    "type": "name",
                    "vals": ["test"],
                },
                {
                    "type": "cn",
                    "vals": ["test"],
                },
                {
                    "type": "objectClass",
                    "vals": ["organization", "top"],
                },
                {
                    "type": "memberOf",
                    "vals": [
                        "cn=domain admins,cn=groups,dc=md,dc=test",
                    ],
                },
            ],
        },
    )

    assert response.json().get("resultCode") == LDAPCodes.SUCCESS

    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=Test,dc=md,dc=test",
            "attributes": [
                {
                    "type": "name",
                    "vals": ["test"],
                },
                {
                    "type": "cn",
                    "vals": ["test"],
                },
                {
                    "type": "objectClass",
                    "vals": ["organization", "top"],
                },
                {
                    "type": "memberOf",
                    "vals": [
                        "cn=domain admins,cn=groups,dc=md,dc=test",
                    ],
                },
            ],
        },
    )

    assert response.json().get("resultCode") == LDAPCodes.ENTRY_ALREADY_EXISTS
