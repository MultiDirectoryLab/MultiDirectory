"""Test policy api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Network

import httpx
import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import NetworkPolicy


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_add_policy(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test api policy add and read."""
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

    raw_response = await http_client.post("/policy", json={
        "name": "local seriveses",
        "netmasks": raw_netmasks,
        "priority": 2,
        'groups': ['cn=domain admins,cn=groups,dc=md,dc=test'],
    }, headers=login_headers)

    assert raw_response.status_code == 201
    assert raw_response.json()["netmasks"] == compare_netmasks
    assert raw_response.json()["enabled"] is True

    raw_response = await http_client.get("/policy", headers=login_headers)
    response = raw_response.json()

    for pol in response:
        pol.pop('id')

    assert response == [
        {
            'enabled': True,
            'name': 'Default open policy',
            'netmasks': ['0.0.0.0/0'],
            'raw': ['0.0.0.0/0'],
            'groups': [],
            'priority': 1,
            'mfa_groups': [],
            'mfa_status': 0,
        },
        {
            'enabled': True,
            'name': 'local seriveses',
            'netmasks': compare_netmasks,
            'raw': raw_netmasks,
            'groups': ['cn=domain admins,cn=groups,dc=md,dc=test'],
            'priority': 2,
            'mfa_groups': [],
            'mfa_status': 0,
        },
    ]


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_update_policy(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Update policy."""
    raw_response = await http_client.get("/policy", headers=login_headers)
    assert raw_response.status_code == status.HTTP_200_OK
    response = raw_response.json()

    pol_id = response[0].pop('id')

    assert response == [
        {
            'enabled': True,
            'name': 'Default open policy',
            'netmasks': ['0.0.0.0/0'],
            'raw': ['0.0.0.0/0'],
            'priority': 1,
            'mfa_groups': [],
            'mfa_status': 0,
            'groups': [],
        },
    ]

    response = await http_client.put(
        "/policy",
        json={
            'id': pol_id,
            'groups': ['cn=domain admins,cn=groups,dc=md,dc=test'],
            'name': 'Default open policy 2',
        }, headers=login_headers)

    assert response.status_code == status.HTTP_200_OK

    response = response.json()
    response.pop('id')

    assert response == {
        'enabled': True,
        'name': 'Default open policy 2',
        'netmasks': ['0.0.0.0/0'],
        'raw': ['0.0.0.0/0'],
        'groups': ['cn=domain admins,cn=groups,dc=md,dc=test'],
        'mfa_groups': [],
        'mfa_status': 0,
        'priority': 1,
    }

    response = await http_client.get("/policy", headers=login_headers)
    assert response.status_code == status.HTTP_200_OK
    response = response.json()

    response[0].pop('id')

    assert response == [
        {
            'enabled': True,
            'name': 'Default open policy 2',
            'netmasks': ['0.0.0.0/0'],
            'raw': ['0.0.0.0/0'],
            'mfa_groups': [],
            'mfa_status': 0,
            'priority': 1,
            'groups': ['cn=domain admins,cn=groups,dc=md,dc=test'],
        },
    ]


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
async def test_delete_policy(
    http_client: httpx.AsyncClient,
    session: AsyncSession,
    login_headers: dict,
) -> None:
    """Delete policy."""
    session.add(NetworkPolicy(
        name='Local policy',
        netmasks=[IPv4Network('127.100.10.5/32')],
        raw=['127.100.10.5/32'],
        enabled=True,
        priority=2,
    ))
    await session.commit()

    raw_response = await http_client.get("/policy", headers=login_headers)
    assert raw_response.status_code == status.HTTP_200_OK
    response = raw_response.json()

    pol_id = response[0].pop('id')
    pol_id2 = response[1].pop('id')

    assert response[0] == {
        'enabled': True,
        'name': 'Default open policy',
        'netmasks': ['0.0.0.0/0'],
        'raw': ['0.0.0.0/0'],
        'groups': [],
        'mfa_groups': [],
        'mfa_status': 0,
        'priority': 1,
    }

    response = await http_client.delete(
        f"/policy/{pol_id}", headers=login_headers, follow_redirects=False)
    assert response.status_code == 303
    assert response.next_request.url.path == '/api/policy'
    response = await http_client.get("/policy", headers=login_headers)
    assert response.status_code == status.HTTP_200_OK
    response = response.json()

    assert len(response) == 1
    assert response[0]['name'] == "Local policy"
    assert response[0]['priority'] == 1

    response = await http_client.delete(
        f"/policy/{pol_id2}", headers=login_headers)
    assert response.status_code == 422
    assert response.json()['detail'] == "At least one policy should be active"


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
async def test_switch_policy(
    http_client: AsyncClient,
    session: AsyncSession,
    login_headers: dict,
) -> None:
    """Switch policy."""
    session.add(NetworkPolicy(
        name='Local policy',
        netmasks=[IPv4Network('127.100.10.5/32')],
        raw=['127.100.10.5/32'],
        enabled=True,
        priority=2,
    ))
    await session.commit()

    raw_response = await http_client.get("/policy", headers=login_headers)
    assert raw_response.status_code == status.HTTP_200_OK
    response = raw_response.json()

    pol_id = response[0].pop('id')
    pol_id2 = response[1].pop('id')

    assert response[0] == {
        'enabled': True,
        'name': 'Default open policy',
        'netmasks': ['0.0.0.0/0'],
        'raw': ['0.0.0.0/0'],
        'groups': [],
        'mfa_groups': [],
        'mfa_status': 0,
        'priority': 1,
    }

    response = await http_client.patch(
        f"/policy/{pol_id}",
        headers=login_headers,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() is True

    response = await http_client.get("/policy", headers=login_headers)
    assert response.json()[0]['enabled'] is False

    response = await http_client.patch(
        f"/policy/{pol_id2}", headers=login_headers)
    assert response.status_code == 422
    assert response.json()['detail'] == "At least one policy should be active"


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_404(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Delete policy."""
    response = await http_client.get("/policy", headers=login_headers)
    assert response.status_code == status.HTTP_200_OK
    some_id = response.json()[0]['id'] + 1

    response = await http_client.delete(
        f"/policy/{some_id}",
        headers=login_headers,
    )
    assert response.status_code == 404

    response = await http_client.patch(
        f"/policy/{some_id}",
        headers=login_headers,
    )
    assert response.status_code == 404

    response = await http_client.put(
        "/policy",
        json={
            'id': some_id,
            "name": '123',
        },
        headers=login_headers,
    )
    assert response.status_code == 404


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_swap(
        http_client: AsyncClient, login_headers: dict) -> None:
    """Test swap policies."""
    raw_response = await http_client.post(
        "/policy",
        json={
            "name": "local seriveses",
            "netmasks": [
                "127.0.0.1",
                {
                    "start": "172.0.0.2",
                    "end": "172.255.1.5",
                },
                "172.8.4.0/24",
            ],
            "priority": 2,
            'groups': ['cn=domain admins,cn=groups,dc=md,dc=test'],
        },
        headers=login_headers,
    )

    raw_get_response = await http_client.get("/policy", headers=login_headers)
    get_response = raw_get_response.json()

    assert get_response[0]['priority'] == 1
    assert get_response[0]['name'] == "Default open policy"
    assert get_response[1]['priority'] == 2

    swap_response = await http_client.post(
        "/policy/swap",
        json={
            'first_policy_id': get_response[0]['id'],
            'second_policy_id': get_response[1]['id'],
        },
        headers=login_headers,
    )

    assert swap_response.json() == {
        "first_policy_id": get_response[0]['id'],
        "first_policy_priority": 2,
        "second_policy_id": get_response[1]['id'],
        "second_policy_priority": 1,
    }

    raw_response = await http_client.get("/policy", headers=login_headers)
    response = raw_response.json()

    assert response[0]['priority'] == 1
    assert response[0]['groups'] == [
        'cn=domain admins,cn=groups,dc=md,dc=test']
    assert response[1]['priority'] == 2
    assert response[1]['name'] == "Default open policy"
