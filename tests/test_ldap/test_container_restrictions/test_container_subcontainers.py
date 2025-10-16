"""Test Container subcontainer restrictions.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import tempfile

import pytest

from config import Settings
from ldap_protocol.ldap_codes import LDAPCodes
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.parametrize(
    ("dn", "rdn_attr", "rdn_value", "object_classes"),
    [
        (
            "cn=testcontainer,cn=users,dc=md,dc=test",
            "cn",
            "testcontainer",
            ["container"],
        ),
        (
            "ou=testou,cn=users,dc=md,dc=test",
            "ou",
            "testou",
            ["organizationalUnit"],
        ),
        (
            "cn=testuser,cn=users,dc=md,dc=test",
            "cn",
            "testuser",
            ["user", "organizationalPerson"],
        ),
        (
            "cn=testgroup,cn=groups,dc=md,dc=test",
            "cn",
            "testgroup",
            ["group", "posixGroup"],
        ),
        (
            "cn=testcomputer,cn=computers,dc=md,dc=test",
            "cn",
            "testcomputer",
            ["computer", "organizationalPerson"],
        ),
    ],
)
async def test_entity_creation_in_container(
    settings: Settings,
    creds: TestCreds,
    dn: str,
    rdn_attr: str,
    rdn_value: str,
    object_classes: list[str],
) -> None:
    """Test entity creation restrictions inside Container using LDAP add."""

    async def try_add() -> int:
        """Try to add the entity using ldapadd."""
        with tempfile.NamedTemporaryFile("w") as file:
            ldif_content = f"dn: {dn}\n"
            ldif_content += f"{rdn_attr}: {rdn_value}\n"
            ldif_content += "objectClass: top\n"

            for obj_class in object_classes:
                ldif_content += f"objectClass: {obj_class}\n"

            file.write(ldif_content)
            file.seek(0)

            proc = await asyncio.create_subprocess_exec(
                "ldapadd",
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

    result = await try_add()

    assert result == LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS
