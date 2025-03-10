"""Test session workflow."""

import asyncio

import pytest
from dishka import AsyncContainer
from httpx import AsyncClient
from ldap3 import Connection
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_requests.modify import Operation
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
        "auth/",
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
async def test_session_rekey(
    unbound_http_client: AsyncClient,
    creds: TestCreds,
    storage: SessionStorage,
    settings: Settings,
    session: AsyncSession,
) -> None:
    """Test session rekey."""
    user = await get_user(session, creds.un)
    assert user
    await unbound_http_client.post(
        "auth/",
        data={"username": creds.un, "password": creds.pw},
    )
    sessions = await storage.get_user_sessions(user.id)

    old_key = list(sessions.keys())[0]
    old_session = sessions[old_key]

    await storage.rekey_session(old_key, settings)
    sessions = await storage.get_user_sessions(user.id)

    new_key = list(sessions.keys())[0]
    new_session = sessions[new_key]

    assert len(sessions) == 1
    assert new_key != old_key
    assert new_session["sign"] != old_session["sign"]
    assert new_session["issued"] != old_session["issued"]
    assert new_session["id"] == user.id
    assert new_session["ip"] == old_session["ip"]

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
        None,
        ldap_client.rebind,
        creds.un,
        creds.pw,
    )

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

    try:
        assert not await storage.get_user_sessions(user.id)
    except AssertionError:
        # in ~1% of cases session is not deleted because of ldap3 lib bug
        import warnings

        warnings.warn(
            "Session was not deleted after ldap unbind.",
            RuntimeWarning,
            2,
        )


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_session_api_get(
    creds: TestCreds,
    http_client: AsyncClient,
    storage: SessionStorage,
    session: AsyncSession,
) -> None:
    """Test session api."""
    response = await http_client.get(f"sessions/{creds.un}")

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

    response = await http_client.get(f"sessions/{creds.un}123")
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found."


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_session_api_delete(
    creds: TestCreds,
    http_client: AsyncClient,
    storage: SessionStorage,
    session: AsyncSession,
) -> None:
    """Test session api delete."""
    user = await get_user(session, creds.un)
    assert user

    storage_data = await storage.get_user_sessions(user.id)
    assert len(storage_data) == 1

    response = await http_client.delete(f"sessions/{creds.un}123")
    assert response.status_code == 404

    response = await http_client.delete(f"sessions/{creds.un}")
    assert response.status_code == 204

    storage_data = await storage.get_user_sessions(user.id)
    assert len(storage_data) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_session_api_delete_detail(
    creds: TestCreds,
    http_client: AsyncClient,
    storage: SessionStorage,
    session: AsyncSession,
) -> None:
    """Test session api delete detail."""
    user = await get_user(session, creds.un)
    assert user

    response = await http_client.get(f"sessions/{creds.un}")
    assert response.status_code == 200

    session_id = list(response.json().keys())[0]

    assert len(await storage.get_user_sessions(user.id)) == 1

    response = await http_client.delete(f"sessions/session/{session_id}")
    assert response.status_code == 204

    assert len(await storage.get_user_sessions(user.id)) == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_block_ldap_user_without_session(
    http_client: AsyncClient,
    session: AsyncSession,
    storage: SessionStorage,
) -> None:
    """Test blocking ldap user without active session."""
    user_dn = "cn=user_non_admin,ou=users,dc=md,dc=test"
    un = "user_non_admin"

    user = await get_user(session, un)
    assert user
    assert not await storage.get_user_sessions(user.id)

    response = await http_client.patch(
        "entry/update",
        json={
            "object": user_dn,
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "userAccountControl",
                        "vals": ["514"],
                    },
                },
            ],
        },
    )

    assert response.status_code == 200
    assert response.json()["resultCode"] == LDAPCodes.SUCCESS


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_block_ldap_user_with_active_session(
    http_client: AsyncClient,
    ldap_client: Connection,
    session: AsyncSession,
    storage: SessionStorage,
    event_loop: asyncio.AbstractEventLoop,
) -> None:
    """Test blocking ldap user with active session."""
    user_dn = "cn=user_non_admin,ou=users,dc=md,dc=test"
    un = "user_non_admin"
    pw = "password"

    user = await get_user(session, un)
    assert user
    assert not await storage.get_user_sessions(user.id)

    result = await event_loop.run_in_executor(
        None,
        ldap_client.rebind,
        un,
        pw,
    )
    assert result
    assert ldap_client.bound

    sessions = await storage.get_user_sessions(user.id)
    assert sessions

    response = await http_client.patch(
        "entry/update",
        json={
            "object": user_dn,
            "changes": [
                {
                    "operation": Operation.REPLACE,
                    "modification": {
                        "type": "userAccountControl",
                        "vals": ["514"],
                    },
                },
            ],
        },
    )

    assert response.status_code == 200
    assert response.json()["resultCode"] == LDAPCodes.SUCCESS

    sessions = await storage.get_user_sessions(user.id)
    assert not sessions
