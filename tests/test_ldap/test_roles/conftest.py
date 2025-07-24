"""Conftest.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import tempfile

import pytest_asyncio

from config import Settings
from ldap_protocol.roles.role_dao import RoleDAO
from models import Role
from tests.conftest import TestCreds

BASE_DN = "dc=md,dc=test"


@pytest_asyncio.fixture(scope="function")
async def custom_role(role_dao: RoleDAO) -> Role:
    """Fixture to create a custom role for testing."""
    return await role_dao.create_role(
        role_name="Custom Role",
        creator_upn=None,
        is_system=False,
        groups_dn=["cn=domain users,cn=groups,dc=md,dc=test"],
    )


async def run_ldap_search(
    settings: Settings,
    creds: TestCreds,
    search_base: str = "dc=md,dc=test",
) -> tuple[int, list[str]]:
    """Run ldapsearch command and return the result."""
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
        search_base,
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    return result, data


async def run_ldap_modify(
    settings: Settings,
    creds: TestCreds,
    dn: str,
    attribute: str,
    value: str,
) -> int:
    """Run ldapmodify command to modify an LDAP entry."""
    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            (
                f"dn: {dn}\n"
                "changetype: modify\n"
                f"replace: {attribute}\n"
                f"{attribute}: {value}\n"
                "-\n"
            )
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            "ldapmodify",
            "-vvv",
            "-H",
            f"ldap://{settings.HOST}:{settings.PORT}",
            "-D",
            "user_non_admin",
            "-x",
            "-w",
            creds.pw,
            "-f",
            file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        return await proc.wait()


async def perform_ldap_search_and_validate(
    settings: Settings,
    creds: TestCreds,
    search_base: str,
    expected_dn: list[str],
    expected_attrs_present: list[str],
    expected_attrs_absent: list[str],
) -> None:
    """Perform LDAP search and validate results."""
    result, data = await run_ldap_search(
        settings,
        creds,
        search_base=search_base,
    )

    dn_list = [d for d in data if d.startswith("dn:")]

    assert result == 0
    assert sorted(dn_list) == sorted(expected_dn)

    for expected in expected_attrs_present:
        assert expected in data

    for unexpected in expected_attrs_absent:
        assert unexpected not in data
