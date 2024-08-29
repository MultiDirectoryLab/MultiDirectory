"""Test API.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import uuid

import pytest
from httpx import AsyncClient

from app.ldap_protocol.dialogue import LDAPCodes, Operation


@pytest.mark.asyncio
@pytest.mark.usefixtures('session')
async def test_api_before_setup(http_client: AsyncClient) -> None:
    """Test api before setup."""
    response = await http_client.get("auth/me")

    assert response.status_code == 401


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_root_dse(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test api root dse."""
    response = await http_client.post(
        "entry/search",
        headers=login_headers,
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
        data['search_result'][0]['partial_attributes'],
        key=lambda x: x['type'],
    )

    aquired_attrs = [attr['type'] for attr in attrs]

    root_attrs = [
        'LDAPServiceName', 'currentTime',
        'defaultNamingContext', 'dnsHostName',
        'domainFunctionality', 'dsServiceName',
        'highestCommittedUSN', 'namingContexts',
        'rootDomainNamingContext', 'vendorVersion',
        'schemaNamingContext', 'serverName',
        'serviceName', 'subschemaSubentry',
        'supportedCapabilities', 'supportedControl',
        'supportedLDAPPolicies', 'supportedLDAPVersion',
        'supportedSASLMechanisms', 'vendorName',
    ]

    assert data['search_result'][0]['object_name'] == ""
    assert all(
        attr in aquired_attrs
        for attr in root_attrs
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_search(
        http_client: AsyncClient, login_headers: dict) -> None:
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
        headers=login_headers,
    )

    response = raw_response.json()

    assert response['resultCode'] == LDAPCodes.SUCCESS

    sub_dirs = [
        "cn=groups,dc=md,dc=test",
        "ou=users,dc=md,dc=test",
    ]
    assert all(
        obj['object_name'] in sub_dirs
        for obj in response['search_result']
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_search_filter_memberof(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test api search."""
    member = 'cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test'
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
        headers=login_headers,
    )

    response = raw_response.json()

    assert response['resultCode'] == LDAPCodes.SUCCESS
    assert response['search_result'][0]['object_name'] == member


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_search_filter_member(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test api search."""
    member = 'cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test'
    group = 'cn=developers,cn=groups,dc=md,dc=test'
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
            "attributes": [],
            "page_number": 1,
        },
        headers=login_headers,
    )

    response = raw_response.json()

    assert response['resultCode'] == LDAPCodes.SUCCESS
    assert response['search_result'][0]['object_name'] == group


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_search_filter_objectguid(
        http_client: AsyncClient, login_headers: dict) -> None:
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
        headers=login_headers,
    )
    data = raw_response.json()

    hex_guid = None
    entry_dn = data['search_result'][3]['object_name']

    for attr in data['search_result'][3]['partial_attributes']:
        if attr['type'] == 'objectGUID':
            hex_guid = attr['vals'][0]
            break

    assert hex_guid is not None, 'objectGUID attribute is missing'

    object_guid = str(uuid.UUID(bytes_le=bytes(bytearray.fromhex(hex_guid))))

    raw_response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 2,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": f"(objectGUID={object_guid})",
            "attributes": [],
            "page_number": 1,
        },
        headers=login_headers,
    )
    data = raw_response.json()

    assert data['search_result'][0]['object_name'] == entry_dn, \
        "User with required objectGUID not found"


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_search_complex_filter(
        http_client: AsyncClient, login_headers: dict) -> None:
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
                        (objectClass=catalog)
                        (objectClass=organizationalUnit)
                        (objectClass=container)
                    )
                    (
                        |(displayName=*user1*)
                        (displayName=*non-exists*)
                    )
                )
                      """,
            "attributes": [],
            "page_number": 1,
        },
        headers=login_headers,
    )
    data = raw_response.json()
    assert data['search_result'][0]['object_name'] == user


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_search_recursive_memberof(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test api search."""
    group = "cn=domain admins,cn=groups,dc=md,dc=test"
    members = [
        "cn=developers,cn=groups,dc=md,dc=test",
        "cn=user0,ou=users,dc=md,dc=test",
        "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test",
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
        headers=login_headers,
    )
    data = response.json()
    assert len(data['search_result']) == len(members)
    assert all(
        obj['object_name'] in members
        for obj in data['search_result']
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_correct_add(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test api correct add."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,dc=md,dc=test",
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
                    "type": "objectClass",
                    "vals": ["organization", "top"],
                },
                {
                    "type": "memberOf",
                    "vals": [
                        "cn=domain admins,cn=groups,dc=md,dc=test",
                    ],
                },
            ],
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert response.status_code == 200
    assert data.get('resultCode') == LDAPCodes.SUCCESS
    assert data.get('errorMessage') == ''


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_correct_add_double_member_of(
        http_client: AsyncClient, login_headers: dict) -> None:
    """
    Test api correct add a group with a register, assigning it to a user, 
    and displaying it in the Search request.
    """
    new_group = "cn=Domain Admins,dc=md,dc=test"
    user = "cn=test,dc=md,dc=test"
    groups = [
        "cn=domain admins,cn=groups,dc=md,dc=test",
        new_group,
    ]

    response = await http_client.post(
        "/entry/add",
        json={
            "entry": new_group,
            "password": None,
            "attributes": [
                {
                    "type": "objectClass",
                    "vals": ["top", "group"]
                },
                {
                    "type": "groupType",
                    "vals": ['-2147483646']
                },
                {
                    "type": "instanceType",
                    "vals": ['4']
                },
            ],
        },
        headers=login_headers,
    )
    data = response.json()

    assert response.status_code == 200
    assert data.get('resultCode') == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": new_group,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": [],
            "page_number": 1,
        },
        headers=login_headers,
    )
    data = response.json()

    assert data['search_result'][0]['object_name'] == new_group
    
    for attr in data['search_result'][0]['partial_attributes']:
        assert attr['type'] != 'memberOf', \
        'memberOf was not specified in the attributes when adding the group'

    response = await http_client.post(
        "/entry/add",
        json={
            "entry": user,
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
                    "type": "objectClass",
                    "vals": ["organization", "top", "user"],
                },
                {
                    "type": "sAMAccountName",
                    "vals": ["test"],
                },
                {
                    "type": "userPrincipalName",
                    "vals": ["test@md.ru"],
                },
                {
                    "type": "mail",
                    "vals": ["test@md.ru"],
                },
                {
                    "type": "displayName",
                    "vals": ["test"],
                },
                {
                    "type": "memberOf",
                    "vals": groups,
                },
            ],
        },
        headers=login_headers,
    )
    data = response.json()

    assert response.status_code == 200
    assert data.get('resultCode') == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": user,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": [],
            "page_number": 1,
        },
        headers=login_headers,
    )
    data = response.json()

    assert response.status_code == 200
    assert data.get('resultCode') == LDAPCodes.SUCCESS
    assert data['search_result'][0]['object_name'] == user
    
    for attr in data['search_result'][0]['partial_attributes']:
        if attr['type'] == 'memberOf':
            assert all(group in groups for group in attr['vals'])
            break
    else:
        raise Exception('memberOf not found')


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_non_auth_user(http_client: AsyncClient) -> None:
    """Test API add for unauthorized user."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
        headers={'Authorization': "Bearer 09e67421-2f92-8ddc-494108a6e04f"},
    )

    data = response.json()

    assert response.status_code == 401
    assert data.get('detail') == 'Could not validate credentials'


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_with_incorrect_dn(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API add a user with incorrect DN."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn!=test,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
        headers=login_headers,
    )

    data = response.json()
    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_with_incorrect_name(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API add a user with incorrect name."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,test,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
        headers=login_headers,
    )

    data = response.json()
    assert data.get('resultCode') == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_with_space_end_name(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API add a user with incorrect name."""
    entry = "cn=test test ,dc=md,dc=test"
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": entry,
            "password": None,
            "attributes": [
                {
                    "type": "objectClass",
                    "vals": ["organization", "top"],
                },
            ],
        },
        headers=login_headers,
    )

    data = response.json()
    assert data.get('resultCode') == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": entry,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": [],
            "page_number": 1,
        },
        headers=login_headers,
    )
    data = response.json()

    assert data['search_result'][0]['object_name'] == entry


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_with_non_exist_parent(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API add a user with non-existen parent."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,ou=testing,dc=md,dc=test",
            "password": "password_test",
            "attributes": [],
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.NO_SUCH_OBJECT


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_double_add(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for adding a user who already exists."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,dc=md,dc=test",
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
                    "type": "objectClass",
                    "vals": ["organization", "top"],
                },
                {
                    "type": "memberOf",
                    "vals": [
                        "cn=domain admins,cn=groups,dc=md,dc=test",
                    ],
                },
            ],
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.ENTRY_ALREADY_EXISTS


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_correct_modify(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for modify object attribute."""
    entry_dn = 'cn=test,dc=md,dc=test'
    new_value = "133632677730000000"
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": entry_dn,
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "accountExpires",
                        "vals": [new_value],
                    },
                },
            ],
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": entry_dn,
            "scope": 0,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": True,
            "filter": "(objectClass=*)",
            "attributes": [],
            "page_number": 1,
        },
        headers=login_headers,
    )

    data = response.json()

    assert data['resultCode'] == LDAPCodes.SUCCESS
    assert data['search_result'][0]['object_name'] == entry_dn

    for attr in data['search_result'][0]['partial_attributes']:
        if attr['type'] == 'accountExpires':
            assert attr['vals'][0] == new_value


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_modify_with_incorrect_dn(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for modify object attribute with incorrect DN."""
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": "cn!=test,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "name",
                        "vals": ["new_test"],
                    },
                },
            ],
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_modify_non_exist_object(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for modify object attribute with non-existen attribute."""
    response = await http_client.patch(
        "/entry/update",
        json={
            "object": "cn=test,dc=md,dc=test",
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "name",
                        "vals": ["new_test"],
                    },
                },
            ],
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.NO_SUCH_OBJECT


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_correct_delete(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for delete object."""
    response = await http_client.request(
        "delete",
        "/entry/delete",
        json={
            "entry": "cn=test,dc=md,dc=test",
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.SUCCESS


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_delete_with_incorrect_dn(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for delete object with incorrect DN."""
    response = await http_client.request(
        "delete",
        "/entry/delete",
        json={
            "entry": "cn!=test,dc=md,dc=test",
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_delete_non_exist_object(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for delete non-existen object."""
    response = await http_client.request(
        "delete",
        "/entry/delete",
        json={
            "entry": "cn=non-exist-object,dc=md,dc=test",
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.NO_SUCH_OBJECT


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_correct_update_dn(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for update DN."""
    old_user_dn = "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test"
    new_user_dn = "cn=new_test2,ou=moscow,ou=russia,ou=users,dc=md,dc=test"
    newrdn_user = new_user_dn.split(',', maxsplit=1)[0]

    old_group_dn = "cn=developers,cn=groups,dc=md,dc=test"
    new_group_dn = "cn=new_developers,cn=groups,dc=md,dc=test"
    newrdn_group, new_superior_group = new_group_dn.split(',', maxsplit=1)

    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": old_user_dn,
            "newrdn": newrdn_user,
            "deleteoldrdn": True,
            "new_superior": None,
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.SUCCESS

    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": old_group_dn,
            "newrdn": newrdn_group,
            "deleteoldrdn": True,
            "new_superior": new_superior_group,
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.SUCCESS

    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=md,dc=test",
            "scope": 3,
            "deref_aliases": 0,
            "size_limit": 1000,
            "time_limit": 10,
            "types_only": False,
            "filter": "(objectClass=*)",
            "attributes": ['memberOf'],
        },
        headers=login_headers,
    )

    data = response.json()

    for entry in data['search_result']:
        assert entry['object_name'] != old_user_dn

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
            "attributes": ['memberOf'],
        },
        headers=login_headers,
    )

    data = response.json()

    assert new_user_dn == data['search_result'][0]['object_name']

    for attr in data['search_result'][0]['partial_attributes']:
        if attr['type'] == 'memberOf':
            assert attr['vals'][0] == new_group_dn


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_update_dn_with_parent(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for update DN."""
    old_user_dn = "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test"
    new_user_dn = "cn=new_test2,ou=users,dc=md,dc=test"
    newrdn_user, new_superior = new_user_dn.split(',', maxsplit=1)

    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": old_user_dn,
            "newrdn": newrdn_user,
            "deleteoldrdn": True,
            "new_superior": new_superior,
        },
        headers=login_headers,
    )

    data = response.json()

    assert data.get('resultCode') == LDAPCodes.SUCCESS

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
            "attributes": ['*'],
        },
        headers=login_headers,
    )

    data = response.json()

    assert data.get('resultCode') == LDAPCodes.SUCCESS
    assert new_user_dn == data['search_result'][0]['object_name']


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_update_dn_non_auth_user(http_client: AsyncClient) -> None:
    """Test API update dn for unauthorized user."""
    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "newrdn": "cn=new_test",
            "deleteoldrdn": True,
            "new_superior": "dc=md,dc=test",
        },
        headers={'Authorization': "Bearer 09e67421-2f92-8ddc-494108a6e04f"},
    )

    data = response.json()
    assert response.status_code == 401
    assert data.get('detail') == 'Could not validate credentials'


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_update_dn_non_exist_superior(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API update dn with non-existen new_superior."""
    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "newrdn": "cn=new_test",
            "deleteoldrdn": True,
            "new_superior": "dc=non-exist,dc=test",
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.NO_SUCH_OBJECT


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_update_dn_non_exist_entry(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API update dn with non-existen entry."""
    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": "cn=non-exist,dc=md,dc=test",
            "newrdn": "cn=new_test",
            "deleteoldrdn": True,
            "new_superior": "dc=md,dc=test",
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.NO_SUCH_OBJECT


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_update_dn_invalid_entry(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API update dn with invalid entry."""
    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": "cn=,",
            "newrdn": "cn=new_test",
            "deleteoldrdn": True,
            "new_superior": "dc=md,dc=test",
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_update_dn_invalid_new_superior(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API update dn with invalid new_superior."""
    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "newrdn": "cn=new_test",
            "deleteoldrdn": True,
            "new_superior": "dc!=,",
        },
        headers=login_headers,
    )

    data = response.json()

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.INVALID_DN_SYNTAX


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_bytes_to_hex(
        http_client: AsyncClient, login_headers: dict) -> None:
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
        headers=login_headers,
    )

    response = raw_response.json()

    assert response['resultCode'] == LDAPCodes.SUCCESS

    for attr in response['search_result'][0]['partial_attributes']:
        if attr['type'] == 'attr_with_bvalue':
            assert attr['vals'][0] == b"any".hex()


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_add_double_case_insensetive(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test api double add."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,dc=md,dc=test",
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
                    "type": "objectClass",
                    "vals": ["organization", "top"],
                },
                {
                    "type": "memberOf",
                    "vals": [
                        "cn=domain admins,cn=groups,dc=md,dc=test",
                    ],
                },
            ],
        },
        headers=login_headers,
    )

    assert response.json().get('resultCode') == LDAPCodes.SUCCESS

    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=Test,dc=md,dc=test",
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
                    "type": "objectClass",
                    "vals": ["organization", "top"],
                },
                {
                    "type": "memberOf",
                    "vals": [
                        "cn=domain admins,cn=groups,dc=md,dc=test",
                    ],
                },
            ],
        },
        headers=login_headers,
    )

    assert response.json().get('resultCode') == LDAPCodes.ENTRY_ALREADY_EXISTS
