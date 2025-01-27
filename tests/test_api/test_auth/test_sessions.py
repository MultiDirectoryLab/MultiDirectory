"""Test session workflow."""

import asyncio

import pytest
from dishka import AsyncContainer
from httpx import AsyncClient
from ldap3 import Connection
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.utils.queries import get_user
from tests.conftest import TestCreds


@pytest.fixture
async def storage(container: AsyncContainer) -> SessionStorage:
    """Return session storage."""
    async with container() as c:
        return await c.get(SessionStorage)


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_session_creation(
    unbound_http_client: AsyncClient,
    creds: TestCreds,
    storage: SessionStorage,
    session: AsyncSession,
) -> None:
    """Test session creation."""
    user = await get_user(session, creds.un)
    assert user
    assert not await storage.get_user_sessions(user.id)

    response = await unbound_http_client.post(
        "auth/token/get",
        data={"username": creds.un, "password": creds.pw},
    )

    assert response.cookies.get("id")
    assert response.status_code == 200

    sessions = await storage.get_user_sessions(user.id)

    assert sessions

    key = list(sessions.keys())[0]

    assert sessions[key]["id"] == user.id
    assert sessions[key]["issued"]
    assert sessions[key]["ip"]
    assert sessions[key]["sign"]

    await storage.clear_user_sessions(user.id)
    assert not await storage.get_user_sessions(user.id)


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_session_creation_ldap_bind_unbind(
    creds: TestCreds,
    storage: SessionStorage,
    session: AsyncSession,
    ldap_client: Connection,
    event_loop: asyncio.AbstractEventLoop,
) -> None:
    """Test session creation for ldap protocol."""
    user = await get_user(session, creds.un)
    assert user
    assert not await storage.get_user_sessions(user.id)

    result = await event_loop.run_in_executor(
        None, ldap_client.rebind, creds.un, creds.pw)

    assert result
    assert ldap_client.bound

    sessions = await storage.get_user_sessions(user.id)

    assert sessions

    key = list(sessions.keys())[0]

    assert sessions[key]["id"] == user.id
    assert sessions[key]["issued"]
    assert sessions[key]["ip"]

    result = await event_loop.run_in_executor(None, ldap_client.unbind)
    assert not ldap_client.bound

    assert not await storage.get_user_sessions(user.id)


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_session_api(
    creds: TestCreds,
    http_client: AsyncClient,
    storage: SessionStorage,
    session: AsyncSession,
) -> None:
    """Test session api."""
    response = await http_client.get(f"session/{creds.un}")

    assert response.status_code == 200
    user = await get_user(session, creds.un)
    assert user
    rdata = response.json()
    storage_data = await storage.get_user_sessions(user.id)

    for k, data in rdata.items():
        assert storage_data[k]["id"] == data["id"]
        assert storage_data[k]["ip"] == data["ip"]
        # pydantic timezone representation is different from ISO
        assert storage_data[k]["issued"][:-6] == data["issued"][:-1]
        assert storage_data[k]["sign"] == data["sign"]

    response = await http_client.get(f"session/{creds.un}123")
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found."

    response = await http_client.delete(f"session/{creds.un}")
    assert response.status_code == 204
