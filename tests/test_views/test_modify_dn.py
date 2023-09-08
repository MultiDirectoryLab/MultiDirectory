"""Test modifyDN protocol."""

import asyncio
import tempfile

import pytest
from sqlalchemy import select

from app.extra import TEST_DATA, setup_enviroment
from app.models.ldap3 import Directory, Path


@pytest.mark.asyncio()
async def test_ldap_modify_dn(session, settings):
    """Test ldapmodify on server."""
    await setup_enviroment(session, dn="multidurectory.test", data=TEST_DATA)
    await session.commit()

    user = TEST_DATA[1]['children'][0]['organizationalPerson']

    dn = "cn=user0,ou=users,dc=multidurectory,dc=test"

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            f"dn: {dn}\n"
            "changetype: modrdn\n"
            "newrdn: uid=user1\n"
            "deleteoldrdn: 1\n"
            "newsuperior: ou=users,dc=multidurectory,dc=test\n"
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapmodify',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        res = await proc.wait()
        print(await proc.stdout.read())
        assert res == 0

    query = select(Directory)\
        .join(Directory.path).filter(Path.path == ["ou=users", "uid=user1"])

    assert await session.scalar(query)
