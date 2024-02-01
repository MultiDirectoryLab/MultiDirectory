"""Test API."""
import pytest

from app.ldap_protocol.dialogue import LDAPCodes


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_api_root_dse(http_client):
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
async def test_api_search(http_client, login_headers):
    """Test api search."""
    response = await http_client.post(
        "entry/search",
        json={
            "base_object": "dc=multidurectory,dc=test",
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

    response = response.json()

    assert response['resultCode'] == LDAPCodes.SUCCESS

    sub_dirs = [
        "cn=groups,dc=multidurectory,dc=test",
        "ou=users,dc=multidurectory,dc=test",
    ]
    assert all(
        obj['object_name'] in sub_dirs
        for obj in response['search_result']
    )
