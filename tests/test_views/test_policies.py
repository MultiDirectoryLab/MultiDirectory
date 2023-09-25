"""Test policy api."""
import asyncio
from ipaddress import IPv4Address, IPv4Network

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.extra import TEST_DATA, setup_enviroment
from app.ldap_protocol.utils import get_group, get_user, is_user_group_valid
from app.models import NetworkPolicy, User


@pytest.mark.asyncio()
async def test_add_policy(http_client, session):
    """Test api policy add and read."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    compare_netmasks = [
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
    ]

    raw_netmasks = [
        "127.0.0.1",
        {"start": "172.0.0.2", "end": "172.255.1.5"},
        "172.8.4.0/24",
    ]

    auth = await http_client.post("auth/token/get", data={
        "username": "user0", "password": "password"})
    login_headers = {'Authorization': f"Bearer {auth.json()['access_token']}"}

    response = await http_client.post("/policy", json={
        "name": "local seriveses",
        "netmasks": raw_netmasks,
        "priority": 2,
        'group': 'cn=domain admins,cn=groups,dc=md,dc=test',
    }, headers=login_headers)

    assert response.status_code == 201
    assert response.json()["netmasks"] == compare_netmasks
    assert response.json()["enabled"] is True

    response = await http_client.get("/policy", headers=login_headers)
    response = response.json()

    for pol in response:
        pol.pop('id')

    assert response == [
        {
            'enabled': True,
            'name': 'Default open policy',
            'netmasks': ['0.0.0.0/0'],
            'raw': ['0.0.0.0/0'],
            'group': None,
            'priority': 1,
        },
        {
            'enabled': True,
            'name': 'local seriveses',
            'netmasks': compare_netmasks,
            'raw': raw_netmasks,
            'group': 'cn=domain admins,cn=groups,dc=md,dc=test',
            'priority': 2,
        },
    ]


@pytest.mark.asyncio()
async def test_update_policy(http_client, session):
    """Update policy."""
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
            'name': 'Default open policy',
            'netmasks': ['0.0.0.0/0'],
            'raw': ['0.0.0.0/0'],
            'priority': 1,
            'group': None,
        },
    ]

    response = await http_client.put(
        "/policy",
        json={
            'id': pol_id,
            'group': 'cn=domain admins,cn=groups,dc=md,dc=test',
            'name': 'Default open policy 2',
        }, headers=login_headers)

    assert response.status_code == 200

    response = response.json()
    response.pop('id')

    assert response == {
        'enabled': True,
        'name': 'Default open policy 2',
        'netmasks': ['0.0.0.0/0'],
        'raw': ['0.0.0.0/0'],
        'group': 'cn=domain admins,cn=groups,dc=md,dc=test',
        'priority': 1,
    }

    response = await http_client.get("/policy", headers=login_headers)
    assert response.status_code == 200
    response = response.json()

    response[0].pop('id')

    assert response == [
        {
            'enabled': True,
            'name': 'Default open policy 2',
            'netmasks': ['0.0.0.0/0'],
            'raw': ['0.0.0.0/0'],
            'priority': 1,
            'group': 'cn=domain admins,cn=groups,dc=md,dc=test',
        },
    ]


@pytest.mark.asyncio()
async def test_delete_policy(http_client, session):
    """Delete policy."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    session.add(NetworkPolicy(
        name='Local policy',
        netmasks=[IPv4Network('127.100.10.5/32')],
        raw=['127.100.10.5/32'],
        enabled=True,
        priority=2,
    ))
    await session.commit()

    auth = await http_client.post("auth/token/get", data={
        "username": "user0", "password": "password"})
    login_headers = {'Authorization': f"Bearer {auth.json()['access_token']}"}

    response = await http_client.get("/policy", headers=login_headers)
    assert response.status_code == 200
    response = response.json()

    pol_id = response[0].pop('id')
    pol_id2 = response[1].pop('id')

    assert response[0] == {
        'enabled': True,
        'name': 'Default open policy',
        'netmasks': ['0.0.0.0/0'],
        'raw': ['0.0.0.0/0'],
        'group': None,
        'priority': 1,
    }

    response = await http_client.delete(
        f"/policy/{pol_id}", headers=login_headers, follow_redirects=True)
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]['name'] == "Local policy"
    assert response.json()[0]['priority'] == 1

    response = await http_client.delete(
        f"/policy/{pol_id2}", headers=login_headers)
    assert response.status_code == 422
    assert response.json()['detail'] == "At least one policy should be active"


@pytest.mark.asyncio()
async def test_switch_policy(http_client, session):
    """Switch policy."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    session.add(NetworkPolicy(
        name='Local policy',
        netmasks=[IPv4Network('127.100.10.5/32')],
        raw=['127.100.10.5/32'],
        enabled=True,
        priority=2,
    ))
    await session.commit()

    auth = await http_client.post("auth/token/get", data={
        "username": "user0", "password": "password"})
    login_headers = {'Authorization': f"Bearer {auth.json()['access_token']}"}

    response = await http_client.get("/policy", headers=login_headers)
    assert response.status_code == 200
    response = response.json()

    pol_id = response[0].pop('id')
    pol_id2 = response[1].pop('id')

    assert response[0] == {
        'enabled': True,
        'name': 'Default open policy',
        'netmasks': ['0.0.0.0/0'],
        'raw': ['0.0.0.0/0'],
        'group': None,
        'priority': 1,
    }

    response = await http_client.patch(
        f"/policy/{pol_id}", headers=login_headers)
    assert response.status_code == 200
    assert response.json() is True

    response = await http_client.get("/policy", headers=login_headers)
    assert response.json()[0]['enabled'] is False

    response = await http_client.patch(
        f"/policy/{pol_id2}", headers=login_headers)
    assert response.status_code == 422
    assert response.json()['detail'] == "At least one policy should be active"


@pytest.mark.asyncio()
async def test_check_policy(handler, session):
    """Delete policy."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    policy = await handler.get_policy(IPv4Address("127.0.0.1"))
    assert policy.netmasks == [IPv4Network("0.0.0.0/0")]


@pytest.mark.asyncio()
async def test_specific_policy_ok(handler, session):
    """Test specific ip."""
    session.add(NetworkPolicy(
        name='Local policy',
        netmasks=[IPv4Network('127.100.10.5/32')],
        raw=['127.100.10.5/32'],
        enabled=True,
        priority=1,
    ))
    await session.commit()
    policy = await handler.get_policy(IPv4Address("127.100.10.5"))
    assert policy.netmasks == [IPv4Network("127.100.10.5/32")]
    assert not await handler.get_policy(IPv4Address("127.100.10.4"))


@pytest.mark.asyncio()
async def test_404(http_client, session):
    """Delete policy."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    auth = await http_client.post("auth/token/get", data={
        "username": "user0", "password": "password"})
    login_headers = {'Authorization': f"Bearer {auth.json()['access_token']}"}

    response = await http_client.get("/policy", headers=login_headers)
    assert response.status_code == 200
    some_id = response.json()[0]['id'] + 1

    response = await http_client.delete(
        f"/policy/{some_id}", headers=login_headers)
    assert response.status_code == 404

    response = await http_client.patch(
        f"/policy/{some_id}", headers=login_headers)
    assert response.status_code == 404

    response = await http_client.put(
        "/policy",
        json={'id': some_id, "name": '123'}, headers=login_headers)
    assert response.status_code == 404


@pytest.mark.asyncio()
async def test_swap(http_client, session):
    """Test swap policies."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    auth = await http_client.post("auth/token/get", data={
        "username": "user0", "password": "password"})
    login_headers = {'Authorization': f"Bearer {auth.json()['access_token']}"}

    response = await http_client.post("/policy", json={
        "name": "local seriveses",
        "netmasks": [
            "127.0.0.1",
            {"start": "172.0.0.2", "end": "172.255.1.5"},
            "172.8.4.0/24",
        ],
        "priority": 2,
    }, headers=login_headers)

    get_response = await http_client.get("/policy", headers=login_headers)
    get_response = get_response.json()

    assert get_response[0]['priority'] == 1
    assert get_response[0]['name'] == "Default open policy"
    assert get_response[1]['priority'] == 2

    swap_response = await http_client.post("/policy/swap", json={
        'first_policy_id': get_response[0]['id'],
        'second_policy_id': get_response[1]['id']}, headers=login_headers)

    assert swap_response.json() == {
        "first_policy_id": get_response[0]['id'],
        "first_policy_priority": 2,
        "second_policy_id": get_response[1]['id'],
        "second_policy_priority": 1,
    }

    response = await http_client.get("/policy", headers=login_headers)
    response = response.json()

    assert response[0]['priority'] == 1
    assert response[1]['priority'] == 2
    assert response[1]['name'] == "Default open policy"


@pytest.mark.asyncio()
async def test_check_policy_group(handler, session, settings):
    """Delete policy."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    user = await get_user(session, "user0")
    policy = await handler.get_policy(IPv4Address('127.0.0.1'))

    assert await is_user_group_valid(user, policy, session)

    group_dir = await get_group(
        'cn=domain admins,cn=groups,dc=md,dc=test', session)

    policy.group = group_dir.group
    await session.commit()

    assert await is_user_group_valid(user, policy, session)


@pytest.mark.asyncio()
async def test_bind_policy(handler, session, settings):
    """Delete policy."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    un = TEST_DATA[1]['children'][0]['organizationalPerson']['sam_accout_name']
    pw = TEST_DATA[1]['children'][0]['organizationalPerson']['password']

    policy = await handler.get_policy(IPv4Address('127.0.0.1'))
    group_dir = await get_group(
        'cn=domain admins,cn=groups,dc=md,dc=test', session)
    policy.group = group_dir.group
    await session.commit()

    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D', un, '-x', '-w', pw)

    result = await proc.wait()
    assert result == 0


@pytest.mark.asyncio()
async def test_bind_policy_missing_group(handler, session, settings):
    """Delete policy."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    un = TEST_DATA[1]['children'][0]['organizationalPerson']['sam_accout_name']
    pw = TEST_DATA[1]['children'][0]['organizationalPerson']['password']

    policy = await handler.get_policy(IPv4Address('127.0.0.1'))
    group_dir = await get_group(
        'cn=domain admins,cn=groups,dc=md,dc=test', session)
    user = await session.scalar(
        select(User).filter_by(display_name="user0")
        .options(selectinload(User.groups)))

    policy.group = group_dir.group
    user.groups.clear()
    await session.commit()

    assert not await is_user_group_valid(user, policy, session)

    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D', un, '-x', '-w', pw)

    result = await proc.wait()
    assert result == 49
