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
from entities import User
from enums import AceType, RoleScope
from ldap_protocol.asn1parser import ASN1Row, TagNumbers
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.ldap_requests import SearchRequest
from ldap_protocol.ldap_requests.contexts import LDAPSearchRequestContext
from ldap_protocol.ldap_responses import SearchResultEntry
from ldap_protocol.policies.network_policy import is_user_group_valid
from ldap_protocol.roles.ace_dao import AccessControlEntryDAO
from ldap_protocol.roles.dataclasses import AccessControlEntryDTO, RoleDTO
from ldap_protocol.roles.role_dao import RoleDAO
from ldap_protocol.utils.queries import get_group, get_groups
from repo.pg.tables import queryable_attr as qa
from tests.conftest import TestCreds
from tests.test_ldap.test_util.test_search_datasets import (
    test_ldap_search_by_rule_bit_and_dataset,
    test_ldap_search_by_rule_bit_or_dataset,
    test_ldap_search_filter_anr_dataset,
)


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
    assert "dn: cn=users,dc=md,dc=test" in data
    assert "dn: cn=user0,cn=users,dc=md,dc=test" in data


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
    assert "dn: cn=user0,cn=users,dc=md,dc=test" in data
    assert "dn: cn=user1,cn=moscow,cn=russia,cn=users,dc=md,dc=test" in data


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize(
    "dataset",
    test_ldap_search_filter_anr_dataset,
)
async def test_ldap_search_filter_anr(
    dataset: dict,
    settings: Settings,
    creds: TestCreds,
) -> None:
    """Test ldapsearch with filter rule "BIT_AND"."""
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
        f"{dataset['filter']}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )  # fmt: skip

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    assert result == 0
    assert data
    if dataset["objects"]:
        for object_dn in dataset["objects"]:
            assert f"dn: {object_dn}" in data
    else:
        assert "dn: " not in data


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize("dataset", test_ldap_search_by_rule_bit_and_dataset)
async def test_ldap_search_by_rule_bit_and(
    dataset: dict,
    settings: Settings,
    creds: TestCreds,
) -> None:
    """Test ldapsearch with filter rule "BIT_AND"."""
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
        f"{dataset['filter']}"
        ")",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )  # fmt: skip

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    assert result == 0
    assert data
    if dataset["objects"]:
        for object_dn in dataset["objects"]:
            assert f"dn: {object_dn}" in data
    else:
        assert "dn: " not in data


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize("dataset", test_ldap_search_by_rule_bit_or_dataset)
async def test_ldap_search_by_rule_bit_or(
    dataset: dict,
    settings: Settings,
    creds: TestCreds,
) -> None:
    """Test ldapsearch with filter rule "BIT_OR"."""
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
        f"(&(objectClass=user){dataset['filter']})",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    assert result == 0
    assert data
    if dataset["objects"]:
        for object_dn in dataset["objects"]:
            assert f"dn: {object_dn}" in data
    else:
        assert "dn: " not in data


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
@pytest.mark.parametrize(
    "filter_",
    [
        "(accountExpires=*)",
        "(accountExpires=134006890408650000)",
        "(accountExpires<=134006890408650000)",
        "(accountExpires>=134006890408650000)",
        "(accountExpires>=0)",  # NOTE: mindate
        "(accountExpires<=2650465908000000000)",  # NOTE: maxdate is December 30, 9999  # noqa: E501
    ],
)
async def test_ldap_search_filter_account_expires(
    filter_: str,
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
        filter_,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    result = await proc.wait()
    assert result == 0


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
    assert "dn: cn=user0,cn=users,dc=md,dc=test" in data


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_bind_policy(
    session: AsyncSession,
    settings: Settings,
    creds: TestCreds,
    ldap_session: LDAPSession,
) -> None:
    """Bind with policy."""
    policy = await ldap_session._get_policy(IPv4Address("127.0.0.1"), session)  # noqa: SLF001
    assert policy

    group = await get_group(
        dn="cn=domain admins,cn=groups,dc=md,dc=test",
        session=session,
    )
    policy.groups.append(group)
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
        "-b",
        "dc=md,dc=test",
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
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
    policy = await ldap_session._get_policy(IPv4Address("127.0.0.1"), session)  # noqa: SLF001

    assert policy

    user_query = (
        select(User)
        .filter_by(display_name="user0")
        .options(selectinload(qa(User.groups)))
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
        "-b",
        "dc=md,dc=test",
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
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
        "-b",
        "dc=md,dc=test",
        "objectclass=*",
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
        base_object="cn=user0,cn=users,dc=md,dc=test",
        scope=0,
        deref_aliases=0,
        size_limit=0,
        time_limit=0,
        types_only=False,
        filter=ASN1Row(
            class_id=128,
            tag_id=TagNumbers.PRESENT,
            value="objectClass",
        ),
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
async def test_ldap_search_empty_request(
    settings: Settings,
    creds: TestCreds,
) -> None:
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
    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    dn_list = [d for d in data if d.startswith("dn:")]
    result = await proc.wait()

    assert result == 0
    assert dn_list == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_ldap_search_access_control_denied(
    settings: Settings,
    creds: TestCreds,
    session: AsyncSession,
    role_dao: RoleDAO,
    access_control_entry_dao: AccessControlEntryDAO,
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
        "dn: cn=user_non_admin,cn=users,dc=md,dc=test",
    ]

    await session.commit()

    await role_dao.create(
        dto=RoleDTO(
            name="Groups Read Role",
            creator_upn=None,
            is_system=False,
            groups=["cn=domain users,cn=groups,dc=md,dc=test"],
        ),
    )

    group_read_ace = AccessControlEntryDTO(
        role_id=role_dao.get_last_id(),
        ace_type=AceType.READ,
        scope=RoleScope.WHOLE_SUBTREE,
        base_dn="cn=groups,dc=md,dc=test",
        attribute_type_id=None,
        entity_type_id=None,
        is_allow=True,
    )

    await access_control_entry_dao.create(group_read_ace)

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
            "dn: cn=domain computers,cn=groups,dc=md,dc=test",
            "dn: cn=domain users,cn=groups,dc=md,dc=test",
            "dn: cn=user_non_admin,cn=users,dc=md,dc=test",
        ],
    )
