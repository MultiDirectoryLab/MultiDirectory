"""Test session workflow."""

import asyncio

import pytest
from httpx import AsyncClient
from ldap3 import Connection
from multidirectory import ldap
from sqlalchemy.ext.asyncio import AsyncSession

from aioldap3 import LDAPConnection
from config import Settings
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_requests.modify import Operation
from ldap_protocol.session_storage import SessionStorage
from ldap_protocol.utils.queries import get_user
from tests.conftest import TestCreds


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
    ldap_client: LDAPConnection,
) -> None:
    """Test session creation for ldap protocol."""
    user = await get_user(session, creds.un)
    assert user
    assert not await storage.get_user_sessions(user.id)

    await ldap_client.bind(creds.un, creds.pw)

    assert ldap_client.is_bound

    sessions = await storage.get_user_sessions(user.id)

    assert sessions

    key = list(sessions.keys())[0]

    assert sessions[key]["id"] == user.id
    assert sessions[key]["issued"]
    assert sessions[key]["ip"]

    await ldap_client.unbind()
    assert ldap_client.is_bound

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
    ldap_client: LDAPConnection,
    session: AsyncSession,
    storage: SessionStorage,
) -> None:
    """Test blocking ldap user with active session."""
    user_dn = "cn=user_non_admin,ou=users,dc=md,dc=test"
    un = "user_non_admin"
    pw = "password"

    user = await get_user(session, un)
    assert user
    assert not await storage.get_user_sessions(user.id)

    await ldap_client.bind(un, pw)
    assert ldap_client.is_bound

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


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_get_sessions_by_protocol(
    storage: SessionStorage,
    creds: TestCreds,
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Test get sessions by protocol."""
    user = await get_user(session, creds.un)
    assert user

    uid = user.id
    http_ip = "192.168.1.1"
    ldap_ip = "192.172.9.3"

    await storage.create_session(
        uid,
        settings,
        extra_data={
            "ip": http_ip,
            "user_agent": storage.get_user_agent_hash(""),
        },
    )

    await storage.create_ldap_session(
        uid,
        "ldap:1234",
        data={"id": uid, "ip": ldap_ip},
    )

    all_sessions = await storage.get_user_sessions(uid)
    assert len(all_sessions) == 2
    key = list(all_sessions.keys())[0]
    assert all_sessions[key]["id"] == user.id

    http_sessions = await storage.get_user_sessions(uid, "http")
    assert len(http_sessions) == 1
    key = list(http_sessions.keys())[0]
    assert http_sessions[key]["id"] == user.id
    assert http_sessions[key]["ip"] == http_ip

    ldap_sessions = await storage.get_user_sessions(uid, "ldap")
    assert len(ldap_sessions) == 1
    key = list(ldap_sessions.keys())[0]
    assert ldap_sessions[key]["id"] == user.id
    assert ldap_sessions[key]["ip"] == ldap_ip

    ip_all_sessions = await storage.get_ip_sessions(http_ip)
    assert len(ip_all_sessions) == 1
    key = list(ip_all_sessions.keys())[0]
    assert ip_all_sessions[key]["id"] == user.id
    assert ip_all_sessions[key]["ip"] == http_ip

    ip_http_sessions = await storage.get_ip_sessions(http_ip, "http")
    assert len(ip_http_sessions) == 1
    key = list(ip_http_sessions.keys())[0]
    assert ip_http_sessions[key]["id"] == user.id
    assert ip_http_sessions[key]["ip"] == http_ip

    ip_ldap_sessions = await storage.get_ip_sessions(ldap_ip, "ldap")
    assert len(ip_ldap_sessions) == 1
    key = list(ip_ldap_sessions.keys())[0]
    assert ip_ldap_sessions[key]["id"] == user.id
    assert ip_ldap_sessions[key]["ip"] == ldap_ip

    assert not await storage.get_ip_sessions(ldap_ip, "http")
    assert not await storage.get_ip_sessions(http_ip, "ldap")


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_delete_user_session(
    storage: SessionStorage,
    creds: TestCreds,
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Test delete user session."""
    user = await get_user(session, creds.un)
    assert user

    uid = user.id
    http_ip = "192.168.1.1"
    ldap_ip = "192.172.9.3"

    session_key = await storage.create_session(
        uid,
        settings,
        extra_data={
            "ip": http_ip,
            "user_agent": storage.get_user_agent_hash(""),
        },
    )
    session_id, _ = session_key.split(".")

    await storage.create_ldap_session(
        uid, "ldap:1234", data={"id": uid, "ip": ldap_ip}
    )

    all_sessions = await storage.get_user_sessions(uid)
    assert len(all_sessions) == 2

    await storage.delete_user_session(session_id)

    assert await storage.get_user_sessions(uid, "ldap")
    assert await storage.get_ip_sessions(ldap_ip)
    assert not await storage.get_user_sessions(uid, "http")
    assert not await storage.get_ip_sessions(http_ip)

    await storage.delete_user_session("ldap:1234")

    assert not await storage.get_ip_sessions(ldap_ip)
    assert not await storage.get_user_sessions(uid)


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_clear_user_sessions(
    storage: SessionStorage,
    creds: TestCreds,
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Test clear user sessions."""
    user = await get_user(session, creds.un)
    assert user

    uid = user.id
    http_ip = "192.168.1.1"
    ldap_ip = "192.172.9.3"

    for _ in range(5):
        await storage.create_session(
            uid,
            settings,
            extra_data={
                "ip": http_ip,
                "user_agent": storage.get_user_agent_hash(""),
            },
        )

    for i in range(10):
        await storage.create_ldap_session(
            uid, f"ldap:{i}", data={"id": uid, "ip": ldap_ip}
        )

    all_sessions = await storage.get_user_sessions(uid)
    assert len(all_sessions) == 15

    http_sessions = await storage.get_user_sessions(uid, "http")
    assert len(http_sessions) == 5

    ldap_sessions = await storage.get_user_sessions(uid, "ldap")
    assert len(ldap_sessions) == 10

    ip_ldap_sessions = await storage.get_ip_sessions(ldap_ip)
    assert len(ip_ldap_sessions) == 10

    ip_http_sessions = await storage.get_ip_sessions(http_ip)
    assert len(ip_http_sessions) == 5

    await storage.clear_user_sessions(uid)

    assert not await storage.get_user_sessions(uid)
    assert not await storage.get_ip_sessions(ldap_ip)
    assert not await storage.get_ip_sessions(http_ip)


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_remove_non_existent_session(
    storage: SessionStorage,
    creds: TestCreds,
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Test remove non-existent session."""
    user = await get_user(session, creds.un)
    assert user

    uid = user.id
    http_ip = "192.168.1.1"
    ldap_ip = "192.172.9.3"

    await storage.create_session(
        uid,
        settings,
        extra_data={
            "ip": http_ip,
            "user_agent": storage.get_user_agent_hash(""),
        },
    )

    await storage.create_ldap_session(
        uid, "ldap:1234", data={"id": uid, "ip": ldap_ip}
    )

    all_sessions = await storage.get_user_sessions(uid)
    assert len(all_sessions) == 2

    await storage.delete(["ldap:1234"])  # type: ignore

    all_sessions = await storage.get_user_sessions(uid)
    assert len(all_sessions) == 1
