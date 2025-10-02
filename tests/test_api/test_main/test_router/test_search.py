"""Test API Search.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from httpx import AsyncClient

from ldap_protocol.ldap_codes import LDAPCodes


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_root_dse(http_client: AsyncClient) -> None:
    """Test api root dse."""
    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "",
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

    attrs = sorted(
        data["search_result"][0]["partial_attributes"],
        key=lambda x: x["type"],
    )

    aquired_attrs = [attr["type"] for attr in attrs]

    root_attrs = [
        "LDAPServiceName",
        "currentTime",
        "defaultNamingContext",
        "dnsHostName",
        "domainFunctionality",
        "dsServiceName",
        "highestCommittedUSN",
        "namingContexts",
        "rootDomainNamingContext",
        "vendorVersion",
        "schemaNamingContext",
        "serverName",
        "serviceName",
        "subschemaSubentry",
        "supportedCapabilities",
        "supportedControl",
        "supportedLDAPPolicies",
        "supportedLDAPVersion",
        "supportedSASLMechanisms",
        "vendorName",
    ]

    assert data["search_result"][0]["object_name"] == ""
    assert all(attr in aquired_attrs for attr in root_attrs)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_search(http_client: AsyncClient) -> None:
    """Test api search."""
    raw_response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 1,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": [],
            "page_number": 1,
        },
    )

    response = raw_response.json()

    assert response["resultCode"] == LDAPCodes.SUCCESS

    sub_dirs = [
        "cn=groups,dc=md,dc=test",
        "ou=users,dc=md,dc=test",
        "ou=testModifyDn1,dc=md,dc=test",
        "ou=testModifyDn3,dc=md,dc=test",
    ]
    assert all(
        obj["object_name"] in sub_dirs for obj in response["search_result"]
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_search_filter_memberof(http_client: AsyncClient) -> None:
    """Test api search."""
    member = "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test"
    raw_response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(memberOf=cn=developers,cn=groups,dc=md,dc=test)",
            "attributes": [],
            "page_number": 1,
        },
    )

    response = raw_response.json()

    assert response["resultCode"] == LDAPCodes.SUCCESS
    assert response["search_result"][0]["object_name"] == member


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_search_filter_member(http_client: AsyncClient) -> None:
    """Test api search."""
    member = "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test"
    group = "cn=developers,cn=groups,dc=md,dc=test"
    raw_response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": f"(member={member})",
            "attributes": ["distinguishedName"],
            "page_number": 1,
        },
    )

    response = raw_response.json()
    assert response["resultCode"] == LDAPCodes.SUCCESS
    dns = (d["object_name"] for d in response["search_result"])
    assert group in dns


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_search_filter_objectguid(http_client: AsyncClient) -> None:
    """Test api search."""
    raw_response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": [],
            "page_number": 1,
        },
    )
    data = raw_response.json()

    hex_guid = None
    entry_dn = data["search_result"][3]["object_name"]

    for attr in data["search_result"][3]["partial_attributes"]:
        if attr["type"] == "objectGUID":
            hex_guid = attr["vals"][0]
            break

    assert hex_guid is not None, "objectGUID attribute is missing"

    raw_response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": f"(objectGUID={hex_guid})",
            "attributes": [],
            "page_number": 1,
        },
    )
    data = raw_response.json()

    assert data["search_result"][0]["object_name"] == entry_dn, (
        "User with required objectGUID not found"
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize(
    "filter_",
    [
        "(accountExpires=*)",
        "(accountExpires=134006890408650000)",
        "(accountExpires<=134006890408650000)",
        "(accountExpires>=134006890408650000)",
        "(accountExpires>=0)",  # NOTE: mindate
        "(accountExpires<=2650465908000000000)",  # NOTE: maxdate is December 30, 9999  # noqa: E501
    ],
)
async def test_api_search_filter_account_expires(
    filter_: str,
    http_client: AsyncClient,
) -> None:
    """Test api search."""
    raw_response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": filter_,
            "attributes": [],
            "page_number": 1,
        },
    )
    response = raw_response.json()
    assert response["resultCode"] == LDAPCodes.SUCCESS


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_search_complex_filter(http_client: AsyncClient) -> None:
    """Test api search."""
    user = "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test"
    raw_response = await http_client.post(
        "entry/search",
        json={
            "base_object": "ou=users,dc=md,dc=test",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": """
                (
                    &(
                        |(objectClass=group)
                        (objectClass=user)
                        (objectClass=ou)
                        (objectClass=organizationalUnit)
                        (objectClass=container)
                    )
                    (
                        |(displayName=*user1*)
                        (displayName=*non-exists*)
                    )
                )
            """,
            "attributes": ["distinguishedName"],
            "page_number": 1,
        },
    )
    data = raw_response.json()
    assert data["search_result"][0]["object_name"] == user


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_search_recursive_memberof(http_client: AsyncClient) -> None:
    """Test api search."""
    group = "cn=domain admins,cn=groups,dc=md,dc=test"
    members = [
        "cn=developers,cn=groups,dc=md,dc=test",
        "cn=user0,ou=users,dc=md,dc=test",
        "cn=user_admin,ou=users,dc=md,dc=test",
        "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test",
        "cn=user_admin_OR1,ou=users,dc=md,dc=test",
        "cn=user_admin_OR2,ou=users,dc=md,dc=test",
        "cn=user_admin_OR3,ou=users,dc=md,dc=test",
    ]
    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": f"(memberOf:1.2.840.113556.1.4.1941:={group})",
            "attributes": [],
            "page_number": 1,
        },
    )
    data = response.json()
    assert len(data["search_result"]) == len(members)
    assert all(obj["object_name"] in members for obj in data["search_result"])


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize(
    "dataset",
    [
        {
            "filter_": "(userAccountControl:1.2.840.113556.1.4.803:=512)",
            "count": 6,
        },
        {
            "filter_": "(userAccountControl:1.2.840.113556.1.4.803:=2)",
            "count": 2,
        },
        {
            "filter_": "(useraccountcontrol:1.2.840.113556.1.4.803:=514)",
            "count": 1,
        },
        {
            "filter_": "(useraccountcontrol:1.2.840.113556.1.4.803:=0)",
            "count": 7,
        },
    ],
)
async def test_api_search_by_rule_bit_and(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test api search."""
    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": dataset["filter_"],
            "attributes": ["userAccountControl"],
            "page_number": 1,
        },
    )
    data = response.json()
    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert len(data["search_result"]) == dataset["count"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize(
    "dataset",
    [
        {
            "filter_": "(userAccountControl:1.2.840.113556.1.4.804:=514)",
            "count": 7,
        },
        {
            "filter_": "(userAccountControl:1.2.840.113556.1.4.804:=18)",
            "count": 2,
        },
        {
            "filter_": "(useraccountcontrol:1.2.840.113556.1.4.804:=32)",
            "count": 0,
        },
        {
            "filter_": "(userAccountControl:1.2.840.113556.1.4.804:=0)",
            "count": 0,
        },
    ],
)
async def test_api_search_by_rule_bit_or(
    dataset: dict,
    http_client: AsyncClient,
) -> None:
    """Test api search."""
    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": dataset["filter_"],
            "attributes": ["userAccountControl"],
            "page_number": 1,
        },
    )
    data = response.json()
    assert data.get("resultCode") == LDAPCodes.SUCCESS
    assert len(data["search_result"]) == dataset["count"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_bytes_to_hex(http_client: AsyncClient) -> None:
    """Test api search."""
    raw_response = await http_client.post(
        "entry/search",
        json={
            "base_object": "cn=user0,ou=users,dc=md,dc=test",
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

    response = raw_response.json()

    assert response["resultCode"] == LDAPCodes.SUCCESS

    for attr in response["search_result"][0]["partial_attributes"]:
        if attr["type"] == "attr_with_bvalue":
            assert attr["vals"][0] == b"any".hex()


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_search_by_entity_type_name(
    http_client: AsyncClient,
) -> None:
    """Test api search by entity type name."""
    entity_type_name = "User"

    raw_response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": f"(entitytypename={entity_type_name})",
            "attributes": ["*"],
            "page_number": 1,
        },
    )

    response = raw_response.json()

    assert response["resultCode"] == LDAPCodes.SUCCESS
    assert response["search_result"]

    for obj in response["search_result"]:
        for attr in obj["partial_attributes"]:
            if attr["type"] == "entityTypeName":
                assert attr["vals"] == [entity_type_name]
                break
        else:
            pytest.fail(
                f"Entity type name '{entity_type_name}' not found in attributes",  # noqa: E501
            )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_api_empty_search(
    http_client: AsyncClient,
) -> None:
    """Test api empty search."""
    entity_type_name = "User"
    raw_response = await http_client.post(
        "entry/search",
        json={
            "base_object": "",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": f"(entitytypename={entity_type_name})",
            "attributes": ["*"],
            "page_number": 1,
        },
    )

    response = raw_response.json()

    assert response["resultCode"] == LDAPCodes.SUCCESS
    assert not response["search_result"]
