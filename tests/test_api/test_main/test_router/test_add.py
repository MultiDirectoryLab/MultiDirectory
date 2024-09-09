"""Test API Add.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import pytest
from httpx import AsyncClient

from app.ldap_protocol.dialogue import LDAPCodes


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_correct_add(
        http_client: AsyncClient, login_headers: dict) -> None:
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
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert response.status_code == 200
    assert data.get('resultCode') == LDAPCodes.SUCCESS
    assert data.get('errorMessage') == ''


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_correct_add_double_member_of(
        http_client: AsyncClient, login_headers: dict) -> None:
    """
    Test api correct add a group with a register, assigning it to a user,
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
                    "vals": ['-2147483646'],
                },
                {
                    "type": "instanceType",
                    "vals": ['4'],
                },
            ],
        },
        headers=login_headers,
    )
    data = response.json()

    assert response.status_code == 200
    assert data.get('resultCode') == LDAPCodes.SUCCESS

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
        headers=login_headers,
    )
    data = response.json()

    assert data['search_result'][0]['object_name'] == new_group

    for attr in data['search_result'][0]['partial_attributes']:
        assert attr['type'] != 'memberOf'

    response = await http_client.post(
        "/entry/add",
        json={
            "entry": user,
            "password": "P@ssw0rd",
            "attributes": [
                {
                    "type": "name",
                    "vals": [f"{un}"],
                },
                {
                    "type": "cn",
                    "vals": [f"{un}"],
                },
                {
                    "type": "objectClass",
                    "vals": ["organization", "top", "user"],
                },
                {
                    "type": "sAMAccountName",
                    "vals": [f"{un}"],
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
                    "vals": [f"{un}"],
                },
                {
                    "type": "memberOf",
                    "vals": groups,
                },
            ],
        },
        headers=login_headers,
    )
    data = response.json()

    assert response.status_code == 200
    assert data.get('resultCode') == LDAPCodes.SUCCESS

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
        headers=login_headers,
    )
    data = response.json()

    assert response.status_code == 200
    assert data.get('resultCode') == LDAPCodes.SUCCESS
    assert data['search_result'][0]['object_name'] == user

    created_groups = groups + ["cn=domain users,cn=groups,dc=md,dc=test"]

    for attr in data['search_result'][0]['partial_attributes']:
        if attr['type'] == 'memberOf':
            assert all(group in created_groups for group in attr['vals'])
            break
    else:
        raise Exception('memberOf not found')


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_non_auth_user(http_client: AsyncClient) -> None:
    """Test API add for unauthorized user."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
        headers={'Authorization': "Bearer 09e67421-2f92-8ddc-494108a6e04f"},
    )

    data = response.json()

    assert response.status_code == 401
    assert data.get('detail') == 'Could not validate credentials'


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_with_incorrect_dn(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API add a user with incorrect DN."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn!=test,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
        headers=login_headers,
    )

    data = response.json()
    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_with_incorrect_name(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API add a user with incorrect name."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,test,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
        headers=login_headers,
    )

    data = response.json()
    assert data.get('resultCode') == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_with_space_end_name(
        http_client: AsyncClient, login_headers: dict) -> None:
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
        headers=login_headers,
    )

    data = response.json()
    assert data.get('resultCode') == LDAPCodes.SUCCESS

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
        headers=login_headers,
    )
    data = response.json()

    assert data['search_result'][0]['object_name'] == entry


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_with_non_exist_parent(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API add a user with non-existen parent."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,ou=testing,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.NO_SUCH_OBJECT


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_double_add(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for adding a user who already exists."""
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
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.ENTRY_ALREADY_EXISTS


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_double_case_insensetive(
        http_client: AsyncClient, login_headers: dict) -> None:
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
        headers=login_headers,
    )

    assert response.json().get('resultCode') == LDAPCodes.SUCCESS

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
        headers=login_headers,
    )

    assert response.json().get('resultCode') == LDAPCodes.ENTRY_ALREADY_EXISTS
