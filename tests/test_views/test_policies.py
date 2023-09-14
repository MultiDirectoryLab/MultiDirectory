"""Test policy api."""
from ipaddress import IPv4Address, IPv4Network

import pytest

from app.extra import TEST_DATA, setup_enviroment


@pytest.mark.asyncio()
async def test_add_policy(http_client, session):
    """Test api policy add and read."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    auth = await http_client.post("auth/token/get", data={
        "username": "user0", "password": "password"})
    login_headers = {'Authorization': f"Bearer {auth.json()['access_token']}"}

    response = await http_client.post("/policy", json={
        "name": "local seriveses",
        "netmasks": [
            "127.0.0.1",
            ["172.0.0.2", "172.255.1.5"],
            "172.8.4.0/24",
        ],
    }, headers=login_headers)

    assert response.status_code == 200
    assert response.json() is True

    response = await http_client.get("/policy", headers=login_headers)
    response = response.json()

    for pol in response:
        pol.pop('id')

    assert response == [
        {
            'enabled': True,
            'name': 'default open policy',
            'netmasks': ['0.0.0.0/0'],
        },
        {
            'enabled': True,
            'name': 'local seriveses',
            'netmasks': [
                '127.0.0.1/32', '172.0.0.2/31', '172.0.0.4/30',
                '172.0.0.8/29', '172.0.0.16/28', '172.0.0.32/27',
                '172.0.0.64/26', '172.0.0.128/25', '172.0.1.0/24',
                '172.0.2.0/23', '172.0.4.0/22', '172.0.8.0/21',
                '172.0.16.0/20', '172.0.32.0/19', '172.0.64.0/18',
                '172.0.128.0/17', '172.1.0.0/16', '172.2.0.0/15',
                '172.4.0.0/14', '172.8.0.0/13', '172.16.0.0/12',
                '172.32.0.0/11', '172.64.0.0/10', '172.128.0.0/10',
                '172.192.0.0/11', '172.224.0.0/12', '172.240.0.0/13',
                '172.248.0.0/14', '172.252.0.0/15', '172.254.0.0/16',
                '172.255.0.0/24', '172.255.1.0/30', '172.255.1.4/31',
                '172.8.4.0/24',
            ],
        },
    ]


@pytest.mark.asyncio()
async def test_switch_policy(http_client, session):
    """Switch policy."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    auth = await http_client.post("auth/token/get", data={
        "username": "user0", "password": "password"})
    login_headers = {'Authorization': f"Bearer {auth.json()['access_token']}"}

    response = await http_client.get("/policy", headers=login_headers)
    assert response.status_code == 200
    response = response.json()

    pol_id = response[0].pop('id')

    assert response == [
        {
            'enabled': True,
            'name': 'default open policy',
            'netmasks': ['0.0.0.0/0'],
        },
    ]

    response = await http_client.put(
        "/policy",
        json={'id': pol_id, 'is_enabled': False}, headers=login_headers)
    assert response.status_code == 200

    assert response.json() is True

    response = await http_client.get("/policy", headers=login_headers)
    assert response.status_code == 200
    response = response.json()

    response[0].pop('id')

    assert response == [
        {
            'enabled': False,
            'name': 'default open policy',
            'netmasks': ['0.0.0.0/0'],
        },
    ]


@pytest.mark.asyncio()
async def test_delete_policy(http_client, session):
    """Delete policy."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    auth = await http_client.post("auth/token/get", data={
        "username": "user0", "password": "password"})
    login_headers = {'Authorization': f"Bearer {auth.json()['access_token']}"}

    response = await http_client.get("/policy", headers=login_headers)
    assert response.status_code == 200
    response = response.json()

    pol_id = response[0].pop('id')

    assert response == [
        {
            'enabled': True,
            'name': 'default open policy',
            'netmasks': ['0.0.0.0/0'],
        },
    ]

    response = await http_client.delete(
        "/policy", params={'policy_id': pol_id}, headers=login_headers)
    assert response.status_code == 200

    response = await http_client.get("/policy", headers=login_headers)
    assert response.status_code == 200

    assert response.json() == []


@pytest.mark.asyncio()
async def test_check_policy(http_client, handler, session):
    """Delete policy."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    assert [policy async for policy in handler.get_policies()] \
        == [IPv4Network("0.0.0.0/0")]
    assert await handler.is_ip_allowed(IPv4Address("127.0.0.1"))
