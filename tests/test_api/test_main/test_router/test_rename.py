"""Test API Rename.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from httpx import AsyncClient

from application.ldap_codes import LDAPCodes
from application.ldap_requests.modify import Operation


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_correct_rename_user(http_client: AsyncClient) -> None:
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

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "cn=admin2,dc=md,dc=test",
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
            "page_number": 1,
        },
    )

    data = response.json()
    assert data["resultCode"] == LDAPCodes.SUCCESS
    assert data["search_result"][0]["object_name"] == "cn=admin2,dc=md,dc=test"

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "sAMAccountName":
            assert attr["vals"][0] == "admin2"
            break
    else:
        raise Exception("User without sAMAccountName")

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "displayName":
            assert attr["vals"][0] == "Administrator"
            break
    else:
        raise Exception("User without displayName")


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_computer")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_correct_rename_computer(http_client: AsyncClient) -> None:
    response = await http_client.put(
        "/entry/rename",
        json={
            "object": "cn=mycomputer,dc=md,dc=test",
            "newrdn": "cn=maincomputer",
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "sAMAccountName",
                        "vals": ["__invalid name for error__"],
                    },
                },
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "displayName",
                        "vals": ["Main Computer"],
                    },
                },
            ],
        },
    )

    data = response.json()
    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.UNDEFINED_ATTRIBUTE_TYPE

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "cn=mycomputer,dc=md,dc=test",
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
            "page_number": 1,
        },
    )

    data = response.json()
    assert data["resultCode"] == LDAPCodes.SUCCESS
    assert data["search_result"][0]["object_name"] == "cn=mycomputer,dc=md,dc=test"  # noqa: E501  # fmt: skip

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "name":
            assert attr["vals"][0] == "mycomputer name"
            break
    else:
        raise Exception("Computer without name")
