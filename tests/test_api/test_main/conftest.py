"""Create test user.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import pytest_asyncio
from httpx import AsyncClient

from app.ldap_protocol.dialogue import LDAPCodes, Operation


@pytest_asyncio.fixture(scope='function')
async def adding_test_user(
    http_client: AsyncClient,
    login_headers: dict[str, str],
) -> None:
    """Test api first setup."""
    test_user_dn = "cn=test,dc=md,dc=test"
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": test_user_dn,
            "password": "",
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
                    "type": "testing_attr",
                    "vals": ['test'],
                },
                {
                    "type": "objectClass",
                    "vals": ["organization", "top", "user"],
                },
            ],
        },
        headers=login_headers,
    )
    data = response.json()
    assert data['resultCode'] == LDAPCodes.SUCCESS

    response = await http_client.patch(
        "/entry/update",
        json={
            "object": test_user_dn,
            "changes": [
                {
                    "operation": Operation.ADD,
                    "modification": {
                        "type": "sAMAccountName",
                        "vals": ["Test"],
                    },
                },
                {
                    "operation": Operation.ADD,
                    "modification": {
                        "type": "mail",
                        "vals": ["new_user@md.test"],
                    },
                },
                {
                    "operation": Operation.ADD,
                    "modification": {
                        "type": "userPrincipalName",
                        "vals": ["new_user@md.test"],
                    },
                },
                {
                    "operation": Operation.ADD,
                    "modification": {
                        "type": "displayName",
                        "vals": ["Test User"],
                    },
                },
                {
                    "operation": Operation.ADD,
                    "modification": {
                        "type": "unicodePwd",
                        "vals": ['"\x00P\x00@\x00s\x00s\x00w\x000\x00r\x00d\x00"\x00'],
                    },
                },
                {
                    "operation": Operation.ADD,
                    "modification": {
                        "type": "memberOf",
                        "vals": ["cn=domain admins,cn=groups,dc=md,dc=test"],
                    },
                },
            ],
        },
        headers=login_headers,
    )
    data = response.json()
    assert data['resultCode'] == LDAPCodes.SUCCESS

    auth = await http_client.post(
        "auth/token/get",
        data={
            "username": 'new_user@md.test',
            "password": 'P@ssw0rd',
        })

    assert auth.json()['access_token']
