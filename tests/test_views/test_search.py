import asyncio
from functools import partial

import pytest

from app.extra import TEST_DATA, setup_enviroment


@pytest.mark.asyncio()
async def test_api_root_dse(http_client, session):
    """Test api first setup."""
    await setup_enviroment(session, data=TEST_DATA, dn='md.test')
    await session.commit()

    response = await http_client.post(
        "entry/search", json={
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
    assert all([attr in aquired_attrs for attr in root_attrs])


@pytest.mark.asyncio()
async def test_api_search(http_client, session):
    """Test api first setup."""
    await setup_enviroment(session, data=TEST_DATA, dn='md.test')
    await session.commit()

    user = TEST_DATA[1]['children'][0][
        'organizationalPerson']['sam_accout_name']
    password = TEST_DATA[1]['children'][0]['organizationalPerson']['password']

    auth = await http_client.post("auth/token/get", data={
        "username": user, "password": password})

    login_header = {'Authorization': f"Bearer {auth.json()['access_token']}"}

    response = await http_client.post(
        "entry/search", json={
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
        headers=login_header)

    response = response.json()

    assert response['resultCode'] == 0

    sub_dirs = ["cn=groups,dc=md,dc=test", "ou=users,dc=md,dc=test"]
    assert all(
        [obj['object_name'] in sub_dirs for obj in response['search_result']])


@pytest.mark.asyncio()
async def test_ldap3_search(session, ldap_client, event_loop):
    """Test ldap3 search."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    user = TEST_DATA[1]['children'][0][
        'organizationalPerson']['sam_accout_name']
    password = TEST_DATA[1]['children'][0]['organizationalPerson']['password']

    await event_loop.run_in_executor(
        None, partial(ldap_client.rebind, user=user, password=password))

    result = await event_loop.run_in_executor(
        None,
        partial(ldap_client.search, 'dc=md,dc=test', '(objectclass=*)'))

    assert result
    assert ldap_client.entries


@pytest.mark.asyncio()
async def test_ldap_search(session, settings):
    """Test ldapsearch on server."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D',
        TEST_DATA[1]['children'][0]['organizationalPerson']['sam_accout_name'],
        '-x', '-w',
        TEST_DATA[1]['children'][0]['organizationalPerson']['password'],
        '-b', 'dc=md,dc=test', 'objectclass=*',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    data, _ = await proc.communicate()
    data = data.decode().split('\n')
    result = await proc.wait()

    assert result == 0
    assert "dn: cn=groups,dc=md,dc=test" in data
    assert "dn: ou=users,dc=md,dc=test" in data
    assert "dn: cn=user0,ou=users,dc=md,dc=test" in data
