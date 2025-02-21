"""Test API Modify DN.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import httpx
import pytest
from fastapi import status

from ldap_protocol.ldap_requests.modify import Operation
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_before_setup(
    unbound_http_client: httpx.AsyncClient,
) -> None:
    """Test api before setup."""
    response = await unbound_http_client.get("auth/me")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("session")
async def test_api_auth_after_change_account_exp(
    http_client: httpx.AsyncClient,
) -> None:
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
        "auth/",
        data={
            "username": "new_user@md.test",
            "password": "P@ssw0rd",
        },
    )

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
    )
    auth = await http_client.post(
        "auth/",
        data={
            "username": "new_user@md.test",
            "password": "P@ssw0rd",
        },
    )

    assert auth.cookies.get("id")


@pytest.mark.usefixtures("setup_session")
async def test_refresh_and_logout_flow(
    unbound_http_client: httpx.AsyncClient,
    creds: TestCreds,
) -> None:
    """Test login, refresh and logout cookie flow."""
    await unbound_http_client.post(
        "auth/", data={"username": creds.un, "password": creds.pw}
    )

    old_token = unbound_http_client.cookies.get("id")

    assert old_token

    await unbound_http_client.delete("auth/")

    assert not unbound_http_client.cookies
