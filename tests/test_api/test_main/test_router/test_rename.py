"""Test API Rename.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from httpx import AsyncClient

from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_requests.modify import Operation


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_correct_rename(http_client: AsyncClient) -> None:
    response = await http_client.put(
        "/entry/rename",
        json={
            "object": "cn=test,dc=md,dc=test",
            "newrdn": "cn=admin2",
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "sAMAccountName",
                        "vals": ["admin2"],
                    },
                },
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "displayName",
                        "vals": ["Administrator"],
                    },
                },
            ],
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS
