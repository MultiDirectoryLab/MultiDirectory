"""Create test user.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import pytest_asyncio
from httpx import AsyncClient


@pytest_asyncio.fixture(scope='function')
async def adding_test_user(
    http_client: AsyncClient,
    login_headers: dict[str, str],
) -> None:
    """Test api first setup."""
    await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "password": "P@ssw0rd",
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
                {
                    "type": "memberOf",
                    "vals": [
                        "cn=domain admins,cn=groups,dc=md,dc=test",
                    ],
                },
                {
                    "type": "accountExpires",
                    "vals": ["133632699930000000"],
                },
            ],
        },
        headers=login_headers,
    )
