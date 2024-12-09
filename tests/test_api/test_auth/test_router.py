"""Test api calls.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from typing import Any

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from ldap_protocol.dialogue import LDAPCodes, Operation
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.utils.queries import get_search_path
from models import Directory, Group


async def apply_user_account_control(
    http_client: AsyncClient, user_dn: str, user_account_control_value: str,
) -> dict[str, Any]:
    """Apply userAccountControl value and return response data.

    :param AsyncClient http_client: client
    :param str user_dn: distinguished name of the user
    :param str user_account_control_value: new value to set for the
        `userAccountControl` attribute.
    """
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": user_dn,
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "userAccountControl",
                        "vals": [user_account_control_value],
                    },
                },
            ],
        },
    )
    return response.json()


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_first_setup_and_oauth(
    unbound_http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test api first setup."""
    response = await unbound_http_client.get("/auth/setup")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() is False

    response = await unbound_http_client.post("/auth/setup", json={
        "domain": "md.test",
        "username": "test",
        "user_principal_name": "test",
        "display_name": "test",
        "mail": "test@example.com",
        "password": "Password123",
    })
    assert response.status_code == status.HTTP_200_OK

    response = await unbound_http_client.get("/auth/setup")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() is True

    auth = await unbound_http_client.post("auth/token/get", data={
        "username": "test", "password": "Password123"})
    assert auth.status_code == 200
    assert list(auth.cookies.keys()) == ['access_token', 'refresh_token']

    response = await unbound_http_client.get("auth/me")
    assert response.status_code == status.HTTP_200_OK

    result = response.json()

    assert result["sam_accout_name"] == "test"
    assert result["user_principal_name"] == "test"
    assert result["mail"] == "test@example.com"
    assert result["display_name"] == "test"
    assert result["dn"] == "cn=test,ou=users,dc=md,dc=test"

    result = await session.scalars(
        select(Directory)
        .options(
            joinedload(Directory.group).selectinload(Group.access_policies),
        )
        .filter(
            Directory.path ==
            get_search_path(
                'cn=readonly domain controllers,cn=groups,dc=md,dc=test',
            ),
        ),
    )
    group_dir = result.one()
    assert group_dir.group
    assert group_dir.group.access_policies
    read_only_policy = group_dir.group.access_policies[0]

    assert read_only_policy.can_read
    assert not read_only_policy.can_modify
    assert not read_only_policy.can_delete
    assert not read_only_policy.can_add


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_update_password_and_check_uac(http_client: AsyncClient) -> None:
    """Update password and check userAccountControl attr."""
    user_dn = "cn=user0,ou=users,dc=md,dc=test"

    response = await http_client.patch(
        "entry/update",
        json={
            "object": user_dn,
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "userAccountControl",
                        "vals": ["8389120"],  # normal and paswd expire
                    },
                },
            ],
        },
    )

    assert response.json().get('resultCode') == LDAPCodes.SUCCESS

    response = await http_client.patch(
        "auth/user/password",
        json={
            "identity": user_dn,
            "new_password": "Password123",
        },
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() is None

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": user_dn,
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

    assert data['resultCode'] == LDAPCodes.SUCCESS
    assert data['search_result'][0]['object_name'] == user_dn

    for attr in data['search_result'][0]['partial_attributes']:
        if attr['type'] == 'userAccountControl':
            assert attr['vals'][0] == '512'
            break
    else:
        raise Exception('UserAccountControl not found')


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_update_password(http_client: AsyncClient) -> None:
    """Update policy."""
    response = await http_client.patch(
        "auth/user/password",
        json={
            "identity": "user0",
            "new_password": "Password123",
        },
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() is None

    new_auth = await http_client.post(
        "auth/token/get",
        data={
            "username": "user0",
            "password": "password",
        },
    )
    assert new_auth.status_code == status.HTTP_401_UNAUTHORIZED

    new_auth = await http_client.post(
        "auth/token/get",
        data={
            "username": "user0",
            "password": "Password123",
        },
    )
    assert new_auth.status_code == status.HTTP_200_OK
    token = new_auth.cookies.get('access_token')
    assert token
    assert 'bearer' in token.lower()


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_auth_disabled_user(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Get token with ACCOUNTDISABLE flag in userAccountControl attribute."""
    response = await http_client.post(
        "auth/token/get",
        data={
            "username": "user0",
            "password": "password",
        },
    )

    assert response.status_code == status.HTTP_200_OK

    response = await http_client.patch(
        "entry/update",
        json={
            "object": "cn=user0,ou=users,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "userAccountControl",
                        "vals": ["514"],
                    },
                },
            ],
        },
    )

    kadmin.lock_principal.assert_called()  # type: ignore
    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.SUCCESS

    response = await http_client.post(
        "auth/token/get",
        data={
            "username": "user0",
            "password": "password",
        },
    )

    assert response.status_code == 403


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_block_user_with_new_attributes(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
) -> None:
    """Block user and verify nsAccountLock and shadowExpires attributes."""
    user_dn = "cn=user0,ou=users,dc=md,dc=test"

    data = await apply_user_account_control(
        http_client, user_dn, "514",
    )

    kadmin.lock_principal.assert_called()  # type: ignore

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": user_dn,
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

    assert data['resultCode'] == LDAPCodes.SUCCESS
    assert data['search_result'][0]['object_name'] == user_dn

    attrs = {
        attr['type']: attr['vals'][0]
        for attr in data['search_result'][0]['partial_attributes']
    }
    assert attrs.get('nsAccountLock') == 'true'
    assert attrs.get('shadowExpire').isdigit()


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_unblock_user_and_remove_new_attributes(
    http_client: AsyncClient,
    kadmin: AbstractKadmin,
    session: AsyncSession,
) -> None:
    """Block and unblock user and verify removal attributes."""
    user_dn = "cn=user0,ou=users,dc=md,dc=test"

    data = await apply_user_account_control(
        http_client, user_dn, "514",
    )

    kadmin.lock_principal.assert_called()  # type: ignore

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.SUCCESS

    data = await apply_user_account_control(
        http_client, user_dn, "512",
    )

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.SUCCESS

    dir_ = await session.scalar(
        select(Directory).filter(Directory.name == "user0"))
    session.expire(dir_)

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": user_dn,
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

    assert data['resultCode'] == LDAPCodes.SUCCESS
    assert data['search_result'][0]['object_name'] == user_dn

    attrs = {
        attr['type']: attr['vals'][0]
        for attr in data['search_result'][0]['partial_attributes']
    }
    assert 'nsAccountLock' not in attrs
    assert 'shadowExpire' not in attrs
