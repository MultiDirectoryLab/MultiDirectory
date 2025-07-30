"""Test search with ldaputil.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from ipaddress import IPv4Address

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import Settings
from enums import AceType, RoleScope
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.ldap_requests import SearchRequest
from ldap_protocol.ldap_requests.contexts import LDAPSearchRequestContext
from ldap_protocol.ldap_responses import SearchResultEntry
from ldap_protocol.policies.network_policy import is_user_group_valid
from ldap_protocol.roles.role_dao import AccessControlEntrySchema, RoleDAO
from ldap_protocol.utils.queries import get_group, get_groups
from models import User
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_ldap_search(settings: Settings, creds: TestCreds) -> None:
    """Test ldapsearch on server."""
    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-x",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        creds.un,
        "-w",
        creds.pw,
        "-b",
        "dc=md,dc=test",
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    assert result == 0
    assert "dn: cn=groups,dc=md,dc=test" in data
    assert "dn: ou=users,dc=md,dc=test" in data
    assert "dn: cn=user0,ou=users,dc=md,dc=test" in data


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_ldap_search_filter(
    settings: Settings,
    creds: TestCreds,
) -> None:
    """Test ldapsearch with filter on server."""
    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-x",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        creds.un,
        "-w",
        creds.pw,
        "-b",
        "dc=md,dc=test",
        "(&"
        "(objectClass=user)"
        "(memberOf:1.2.840.113556.1.4.1941:=cn=domain admins,cn=groups,dc=md,\
            dc=test)"
        ")",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    assert result == 0
    assert "dn: cn=user0,ou=users,dc=md,dc=test" in data
    assert "dn: cn=user1,ou=moscow,ou=russia,ou=users,dc=md,dc=test" in data


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_ldap_search_filter_prefix(
    settings: Settings,
    creds: TestCreds,
) -> None:
    """Test ldapsearch with filter on server."""
    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-x",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        creds.un,
        "-w",
        creds.pw,
        "-b",
        "dc=md,dc=test",
        "(description=*desc)",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    assert result == 0
    assert "dn: cn=user0,ou=users,dc=md,dc=test" in data


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_bind_policy(
    session: AsyncSession,
    settings: Settings,
    creds: TestCreds,
    ldap_session: LDAPSession,
) -> None:
    """Bind with policy."""
    policy = await ldap_session._get_policy(IPv4Address("127.0.0.1"), session)
    assert policy

    group_dir = await get_group(
        dn="cn=domain admins,cn=groups,dc=md,dc=test",
        session=session,
    )
    policy.groups.append(group_dir.group)
    await session.commit()

    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        creds.un,
        "-x",
        "-w",
        creds.pw,
    )

    result = await proc.wait()
    assert result == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_bind_policy_missing_group(
    session: AsyncSession,
    ldap_session: LDAPSession,
    settings: Settings,
    creds: TestCreds,
) -> None:
    """Bind policy fail."""
    policy = await ldap_session._get_policy(IPv4Address("127.0.0.1"), session)

    assert policy

    user_query = (
        select(User)
        .filter_by(display_name="user0")
        .options(selectinload(User.groups))
    )
    user = (await session.scalars(user_query)).one()

    policy.groups = await get_groups(
        ["cn=domain admins,cn=groups,dc=md,dc=test"],
        session,
    )
    user.groups.clear()
    await session.commit()

    assert not await is_user_group_valid(user, policy, session)

    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        creds.un,
        "-x",
        "-w",
        creds.pw,
    )

    result = await proc.wait()
    assert result == 49


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_ldap_bind(settings: Settings, creds: TestCreds) -> None:
    """Test ldapsearch on server."""
    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-x",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        creds.un,
        "-w",
        creds.pw,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    result = await proc.wait()
    assert result == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_bvalue_in_search_request(
    ldap_bound_session: LDAPSession,
    ctx_search: LDAPSearchRequestContext,
) -> None:
    """Test SearchRequest with bytes data."""
    request = SearchRequest(
        base_object="cn=user0,ou=users,dc=md,dc=test",
        scope=0,
        deref_aliases=0,
        size_limit=0,
        time_limit=0,
        types_only=False,
        filter=ASN1Row(class_id=128, tag_id=7, value="objectClass"),
        attributes=["*"],
    )
    ctx_search.ldap_session = ldap_bound_session
    result: SearchResultEntry = await anext(request.handle(ctx_search))  # type: ignore

    assert result

    for attr in result.partial_attributes:
        if attr.type == "attr_with_bvalue":
            assert isinstance(attr.vals[0], bytes)


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_ldap_search_access_control_denied(
    settings: Settings,
    creds: TestCreds,
    session: AsyncSession,
    role_dao: RoleDAO,
) -> None:
    """Test ldapsearch on server.

    Default user can read himself.
    User with access control entry can read groups.
    """
    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-x",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        "user_non_admin",
        "-w",
        creds.pw,
        "-b",
        "dc=md,dc=test",
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    dn_list = [d for d in data if d.startswith("dn:")]

    assert result == 0
    assert dn_list == [
        "dn: cn=user_non_admin,ou=users,dc=md,dc=test",
    ]

    await session.commit()

    group_read_role = await role_dao.create_role(
        role_name="Groups Read Role",
        creator_upn=None,
        is_system=False,
        groups_dn=["cn=domain users,cn=groups,dc=md,dc=test"],
    )

    group_read_ace = AccessControlEntrySchema(
        ace_type=AceType.READ,
        scope=RoleScope.WHOLE_SUBTREE,
        base_dn="cn=groups,dc=md,dc=test",
        attribute_type_id=None,
        entity_type_id=None,
        is_allow=True,
    )

    await role_dao.add_access_control_entries(
        role_id=group_read_role.id,
        access_control_entries=[group_read_ace],
    )

    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-x",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        "user_non_admin",
        "-w",
        creds.pw,
        "-b",
        "dc=md,dc=test",
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    dn_list = [d for d in data if d.startswith("dn:")]

    assert result == 0
    assert sorted(dn_list) == sorted(
        [
            "dn: cn=groups,dc=md,dc=test",
            "dn: cn=domain admins,cn=groups,dc=md,dc=test",
            "dn: cn=developers,cn=groups,dc=md,dc=test",
            "dn: cn=domain users,cn=groups,dc=md,dc=test",
            "dn: cn=user_non_admin,ou=users,dc=md,dc=test",
        ],
    )
