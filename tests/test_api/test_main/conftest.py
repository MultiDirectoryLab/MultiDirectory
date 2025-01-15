"""Create test user.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.dns import (
    DNS_MANAGER_IP_ADDRESS_NAME,
    DNS_MANAGER_STATE_NAME,
    DNS_MANAGER_ZONE_NAME,
    DNSManagerState,
)
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_requests.modify import Operation
from models import CatalogueSetting


@pytest_asyncio.fixture(scope="function")
async def adding_test_user(
    app: FastAPI,
    http_client: AsyncClient,
    _force_override_tls: None,
) -> None:
    """Test add user like keycloak."""
    test_user_dn = "cn=test,dc=md,dc=test"
    user_password = '"\x00P\x00@\x00s\x00s\x00w\x000\x00r\x00d\x00"\x00'
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": test_user_dn,
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
                    "type": "testing_attr",
                    "vals": ["test"],
                },
                {
                    "type": "objectClass",
                    "vals": ["organization", "top", "user"],
                },
            ],
        },
    )
    data = response.json()
    assert data["resultCode"] == LDAPCodes.SUCCESS

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
                        "vals": [user_password],
                    },
                },
                {
                    "operation": Operation.ADD,
                    "modification": {
                        "type": "memberOf",
                        "vals": ["cn=domain admins,cn=groups,dc=md,dc=test"],
                    },
                },
                {
                    "operation": Operation.ADD,
                    "modification": {
                        "type": "userAccountControl",
                        "vals": ["0"],
                    },
                },
            ],
        },
    )
    data = response.json()
    assert data["resultCode"] == LDAPCodes.SUCCESS

    async with AsyncClient(
            transport=ASGITransport(app=app, root_path='/api'),
            timeout=3,
            base_url="http://test") as client:

        auth = await client.post(
            "auth/token/get",
            data={
                "username": "new_user@md.test",
                "password": "P@ssw0rd",
            },
        )

        assert auth.cookies.get("access_token")


@pytest_asyncio.fixture(scope='function')
async def add_dns_settings(
    session: AsyncSession,
) -> None:
    """Add DNS manager settings to DB."""
    dns_ip_address = "127.0.0.1"
    domain = "example.com"
    dns_state = DNSManagerState.HOSTED

    session.add_all(
        [
            CatalogueSetting(
                name=DNS_MANAGER_IP_ADDRESS_NAME,
                value=dns_ip_address,
            ),
            CatalogueSetting(
                name=DNS_MANAGER_ZONE_NAME,
                value=domain,
            ),
            CatalogueSetting(
                name=DNS_MANAGER_STATE_NAME,
                value=dns_state,
            ),
        ],
    )
    await session.commit()
