"""Test API Set Primary Group.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from httpx import AsyncClient

from ldap_protocol.ldap_codes import LDAPCodes


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_set_primary_group(http_client: AsyncClient) -> None:
    """Test API for setting primary group."""
    user_dn = "cn=test,dc=md,dc=test"
    group_dn = "cn=domain admins,cn=groups,dc=md,dc=test"

    response = await http_client.post(
        "/entry/set_primary_group",
        json={
            "directory_dn": user_dn,
            "group_dn": group_dn,
        },
    )

    assert response.status_code == 200

    response = await http_client.post(
        "/entry/search",
        json={
            "base_object": user_dn,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["primaryGroupID", "memberOf"],
            "page_number": 1,
        },
    )

    data = response.json()
    assert data["resultCode"] == LDAPCodes.SUCCESS
    assert data["search_result"][0]["object_name"] == user_dn

    primary_group_id = None
    member_of = []
    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "primaryGroupID":
            primary_group_id = attr["vals"][0]
        if attr["type"] == "memberOf":
            member_of = attr["vals"]

    assert primary_group_id is not None
    assert group_dn in member_of
