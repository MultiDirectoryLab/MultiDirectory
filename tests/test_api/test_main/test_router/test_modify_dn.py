"""Test API Modify DN.

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
async def test_api_modify_dn_without_level_change(
    http_client: AsyncClient,
) -> None:
    """Test API for updating DN.

    Change parent while up object level in LDAP tree.
    """
    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "ou=testModifyDn1,dc=md,dc=test",
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
        },
    )
    data = response.json()
    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert (
        data["search_result"][0]["object_name"]
        == "ou=testModifyDn1,dc=md,dc=test"
    )

    response = await http_client.put(
        "/entry/update/dn",
        json={
            # NOTE level is 3
            "entry": "ou=testModifyDn1,dc=md,dc=test",
            "newrdn": "ou=testModifyDn1",
            "deleteoldrdn": True,
            "new_superior": "ou=testModifyDn3,dc=md,dc=test",
        },
    )
    data = response.json()
    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            # NOTE level is 6
            "base_object": "cn=testGroup1,ou=testModifyDn2,ou=testModifyDn1,ou=testModifyDn3,dc=md,dc=test",  # noqa: E501
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
        },
    )
    data = response.json()
    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert (
        data["search_result"][0]["object_name"]
        == "cn=testGroup1,ou=testModifyDn2,ou=testModifyDn1,ou=testModifyDn3,dc=md,dc=test"  # noqa: E501
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_modify_dn_with_level_down(
    http_client: AsyncClient,
) -> None:
    """Test API for updating DN.

    Change parent while lowering object level in LDAP tree.
    """
    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "cn=testGroup1,ou=testModifyDn2,ou=testModifyDn1,dc=md,dc=test",
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
        },
    )
    data = response.json()
    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert (
        data["search_result"][0]["object_name"]
        == "cn=testGroup1,ou=testModifyDn2,ou=testModifyDn1,dc=md,dc=test"
    )

    response = await http_client.put(
        "/entry/update/dn",
        json={
            # NOTE level is 5
            "entry": "cn=testGroup1,ou=testModifyDn2,ou=testModifyDn1,dc=md,dc=test",  # noqa: E501
            "newrdn": "cn=testGroup1",
            "deleteoldrdn": True,
            "new_superior": "ou=testModifyDn1,dc=md,dc=test",
        },
    )
    data = response.json()
    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            # NOTE level is 4
            "base_object": "cn=testGroup1,ou=testModifyDn1,dc=md,dc=test",
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
        },
    )
    data = response.json()
    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert (
        data["search_result"][0]["object_name"]
        == "cn=testGroup1,ou=testModifyDn1,dc=md,dc=test"
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_modify_dn_with_level_up(
    http_client: AsyncClient,
) -> None:
    """Test API for updating DN.

    Change parent while up object level in LDAP tree.
    """
    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "cn=testGroup2,ou=testModifyDn1,dc=md,dc=test",
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
        },
    )
    data = response.json()
    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert (
        data["search_result"][0]["object_name"]
        == "cn=testGroup2,ou=testModifyDn1,dc=md,dc=test"
    )

    response = await http_client.put(
        "/entry/update/dn",
        json={
            # NOTE level is 4
            "entry": "cn=testGroup2,ou=testModifyDn1,dc=md,dc=test",
            "newrdn": "cn=testGroup2",
            "deleteoldrdn": True,
            "new_superior": "ou=testModifyDn2,ou=testModifyDn1,dc=md,dc=test",
        },
    )
    data = response.json()
    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            # NOTE level is 5
            "base_object": "cn=testGroup2,ou=testModifyDn2,ou=testModifyDn1,dc=md,dc=test",  # noqa: E501
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
        },
    )
    data = response.json()
    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert (
        data["search_result"][0]["object_name"]
        == "cn=testGroup2,ou=testModifyDn2,ou=testModifyDn1,dc=md,dc=test"
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_correct_update_dn(http_client: AsyncClient) -> None:
    """Test API for update DN."""
    old_user_dn = "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test"
    newrdn_user = "cn=new_test2"

    old_group_dn = "cn=developers,cn=groups,dc=md,dc=test"
    new_group_dn = "cn=new_developers,cn=groups,dc=md,dc=test"
    newrdn_group = "cn=new_developers"
    new_superior_group = "cn=groups,dc=md,dc=test"

    new_user_dn = ",".join((newrdn_user, new_superior_group))

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": old_user_dn,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
        },
    )
    data = response.json()
    assert isinstance(data, dict)

    old_object_guid = None
    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "objectGUID":
            old_object_guid = attr["vals"][0]
            break

        if attr["type"] == "cn":
            assert attr["vals"] == ["user1"]

    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": old_user_dn,
            "newrdn": newrdn_user,
            "deleteoldrdn": True,
            "new_superior": new_superior_group,
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": new_user_dn,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
        },
    )
    data = response.json()
    assert data["search_result"][0]["object_name"] == new_user_dn
    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "objectGUID":
            assert attr["vals"][0] == old_object_guid
            break

        if attr["type"] == "cn":
            assert attr["vals"] == ["new_test2"]

    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": old_group_dn,
            "newrdn": newrdn_group,
            "deleteoldrdn": True,
            "new_superior": new_superior_group,  # NOTE: new_superior equal old_superior  # noqa: E501
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": new_user_dn,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 0,
            "time_limit": 0,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["memberOf"],
        },
    )

    data = response.json()

    assert new_user_dn == data["search_result"][0]["object_name"]

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "memberOf":
            assert attr["vals"][0] == new_group_dn
            break
    else:
        raise Exception("Groups not found")


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_update_dn_with_parent(http_client: AsyncClient) -> None:
    """Test API for update DN."""
    old_user_dn = "cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test"
    new_user_dn = "cn=new_test2,cn=users,dc=md,dc=test"
    groups_user = None
    newrdn_user, new_superior = new_user_dn.split(",", maxsplit=1)

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": old_user_dn,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 0,
            "time_limit": 0,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
        },
    )

    data = response.json()

    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert old_user_dn == data["search_result"][0]["object_name"]

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "memberOf":
            groups_user = attr["vals"]

    assert groups_user

    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": old_user_dn,
            "newrdn": newrdn_user,
            "deleteoldrdn": True,
            "new_superior": new_superior,
        },
    )

    data = response.json()

    assert data.get("resultCode") == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": new_user_dn,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 0,
            "time_limit": 0,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ["*"],
        },
    )

    data = response.json()

    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert new_user_dn == data["search_result"][0]["object_name"]

    for attr in data["search_result"][0]["partial_attributes"]:
        if attr["type"] == "memberOf":
            assert groups_user == attr["vals"]
            break
    else:
        raise Exception("Groups not found")


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_update_dn_non_auth_user(http_client: AsyncClient) -> None:
    """Test API update dn for unauthorized user."""
    http_client.cookies.clear()
    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "newrdn": "cn=new_test",
            "deleteoldrdn": True,
            "new_superior": "dc=md,dc=test",
        },
    )

    data = response.json()
    assert response.status_code == 401
    assert data.get("detail") == "Could not validate credentials"


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_update_dn_non_exist_superior(
    http_client: AsyncClient,
) -> None:
    """Test API update dn with non-existen new_superior."""
    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "newrdn": "cn=new_test",
            "deleteoldrdn": True,
            "new_superior": "dc=non-exist,dc=test",
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.NO_SUCH_OBJECT


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_update_dn_non_exist_entry(http_client: AsyncClient) -> None:
    """Test API update dn with non-existen entry."""
    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": "cn=non-exist,dc=md,dc=test",
            "newrdn": "cn=new_test",
            "deleteoldrdn": True,
            "new_superior": "dc=md,dc=test",
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.NO_SUCH_OBJECT


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_update_dn_invalid_entry(http_client: AsyncClient) -> None:
    """Test API update dn with invalid entry."""
    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": "cn=,",
            "newrdn": "cn=new_test",
            "deleteoldrdn": True,
            "new_superior": "dc=md,dc=test",
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures("adding_test_user")
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_api_update_dn_invalid_new_superior(
    http_client: AsyncClient,
) -> None:
    """Test API update dn with invalid new_superior."""
    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "newrdn": "cn=new_test",
            "deleteoldrdn": True,
            "new_superior": "dc!=,",
        },
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get("resultCode") == LDAPCodes.INVALID_DN_SYNTAX
