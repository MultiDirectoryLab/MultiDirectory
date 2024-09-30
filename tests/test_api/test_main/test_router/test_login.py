"""Test API Modify DN.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import pytest
from fastapi import status
from httpx import AsyncClient

from app.ldap_protocol.dialogue import Operation


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_api_before_setup(unbound_http_client: AsyncClient) -> None:
    """Test api before setup."""
    response = await unbound_http_client.get("auth/me")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_auth_after_change_account_exp(
        http_client: AsyncClient) -> None:
    """Test api auth."""
    await http_client.patch(
        "/entry/update",
        json={
            "object": "cn=test,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.ADD,
                    "modification": {
                        "type": "accountExpires",
                        "vals": ["133075840000000000"],
                    },
                },
            ],
        },
    )
    auth = await http_client.post(
        "auth/token/get",
        data={
            "username": 'new_user@md.test',
            "password": 'P@ssw0rd',
        })

    assert auth.status_code == status.HTTP_403_FORBIDDEN

    await http_client.patch(
        "/entry/update",
        json={
            "object": "cn=test,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "accountExpires",
                        "vals": ["0"],
                    },
                },
            ],
        },
        headers=login_headers,
    )
    auth = await http_client.post(
        "auth/token/get",
        data={
            "username": 'new_user@md.test',
            "password": 'P@ssw0rd',
        })

    assert auth.json()['access_token']
