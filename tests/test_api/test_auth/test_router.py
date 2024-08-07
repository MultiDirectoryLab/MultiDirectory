"""Test api calls.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
@pytest.mark.filterwarnings("ignore::sqlalchemy.exc.SAWarning")
async def test_first_setup_and_oauth(http_client: AsyncClient) -> None:
    """Test api first setup."""
    response = await http_client.get("/auth/setup")
    assert response.status_code == 200
    assert response.json() is False

    response = await http_client.post("/auth/setup", json={
        "domain": "md.test",
        "username": "test",
        "user_principal_name": "test",
        "display_name": "test",
        "mail": "test@example.com",
        "password": "Password123",
    })
    assert response.status_code == 200

    response = await http_client.get("/auth/setup")
    assert response.status_code == 200
    assert response.json() is True

    auth = await http_client.post("auth/token/get", data={
        "username": "test", "password": "Password123"})
    assert auth.status_code == 200

    login_header = {'Authorization': f"Bearer {auth.json()['access_token']}"}

    response = await http_client.get("auth/me", headers=login_header)
    assert response.status_code == 200

    result = response.json()

    assert result["sam_accout_name"] == "test"
    assert result["user_principal_name"] == "test"
    assert result["mail"] == "test@example.com"
    assert result["display_name"] == "test"
    assert result["dn"] == "cn=test,ou=users,dc=md,dc=test"


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_update_password(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Update policy."""
    response = await http_client.patch(
        "auth/user/password",
        json={
            "identity": "user0",
            "new_password": "Password123",
        },
        headers=login_headers,
    )

    assert response.status_code == 200
    assert response.json() is None

    new_auth = await http_client.post(
        "auth/token/get",
        data={
            "username": "user0",
            "password": "password",
        },
    )
    assert new_auth.status_code == 401

    new_auth = await http_client.post(
        "auth/token/get",
        data={
            "username": "user0",
            "password": "Password123",
        },
    )
    assert new_auth.status_code == 200
    assert new_auth.json()['type'] == 'bearer'
