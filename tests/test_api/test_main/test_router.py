"""Test API."""
import pytest
from httpx import AsyncClient

from app.ldap_protocol.dialogue import LDAPCodes, Operation
from app.ldap_protocol.ldap_responses import INVALID_ACCESS_RESPONSE


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
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
        data['search_result'][0]['partial_attributes'],
        key=lambda x: x['type'],
    )

    aquired_attrs = [attr['type'] for attr in attrs]

    root_attrs = [
        'LDAPServiceName', 'currentTime',
        'defaultNamingContext', 'dnsHostName',
        'domainFunctionality', 'dsServiceName',
        'highestCommittedUSN', 'namingContexts',
        'objectClass', 'rootDomainNamingContext',
        'schemaNamingContext', 'serverName',
        'serviceName', 'subschemaSubentry',
        'supportedCapabilities', 'supportedControl',
        'supportedLDAPPolicies', 'supportedLDAPVersion',
        'supportedSASLMechanisms', 'vendorName',
        'vendorVersion',
    ]

    assert data['search_result'][0]['object_name'] == ""
    assert all(
        attr in aquired_attrs
        for attr in root_attrs
    )


@pytest.mark.asyncio()
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


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_correct_add(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test api correct add."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=test,dc=md,dc=test",
            "password": "password_test",
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


@pytest.mark.asyncio()
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

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.OPERATIONS_ERROR
    assert data.get('errorMessage') == INVALID_ACCESS_RESPONSE['errorMessage']


@pytest.mark.asyncio()
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


@pytest.mark.asyncio()
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


@pytest.mark.asyncio()
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
            "password": "password_test",
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


@pytest.mark.asyncio()
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_correct_modify(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for modify object attribute."""
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
    assert data.get('resultCode') == LDAPCodes.SUCCESS


@pytest.mark.asyncio()
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


@pytest.mark.asyncio()
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


@pytest.mark.asyncio()
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


@pytest.mark.asyncio()
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


@pytest.mark.asyncio()
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


@pytest.mark.asyncio()
@pytest.mark.usefixtures('adding_test_user')
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_correct_update_dn(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test API for update DN."""
    old_user_dn = "cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test"
    new_user_dn = "cn=new_test2,ou=moscow,ou=russia,ou=users,dc=md,dc=test"
    newrdn_user, new_superior_user = new_user_dn.split(',', maxsplit=1)

    old_group_dn = "cn=developers,cn=groups,dc=md,dc=test"
    new_group_dn = "cn=new_developers,cn=groups,dc=md,dc=test"
    newrdn_group, new_superior_group = new_group_dn.split(',', maxsplit=1)

    response = await http_client.put(
        "/entry/update/dn",
        json={
            "entry": old_user_dn,
            "newrdn": newrdn_user,
            "deleteoldrdn": True,
            "new_superior": new_superior_user,
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

    for attr in data['search_result'][0]['partial_attributes']:
        if attr['type'] == 'memberOf':
            assert attr['vals'][0] == new_group_dn


@pytest.mark.asyncio()
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

    assert isinstance(data, dict)
    assert data.get('resultCode') == LDAPCodes.OPERATIONS_ERROR
    assert data.get('errorMessage') == INVALID_ACCESS_RESPONSE['errorMessage']


@pytest.mark.asyncio()
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


@pytest.mark.asyncio()
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
