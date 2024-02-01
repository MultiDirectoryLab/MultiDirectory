"""Test delete."""

import asyncio
import tempfile

import pytest
from sqlalchemy import select

from app.extra import TEST_DATA
from app.models.ldap3 import Directory


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_ldap_delete(session, settings):
    """Test ldapdelete on server."""
    user = TEST_DATA[1]['children'][0]['organizationalPerson']

    dn = "cn=test,dc=multidurectory,dc=test"

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            f"dn: {dn}\n"
            "name: test\n"
            "cn: test\n"
            "objectClass: organization\n"
            "objectClass: top\n"
            "memberOf: cn=domain admins,cn=groups,dc=multidurectory,dc=test\n"
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapadd',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        assert await proc.wait() == 0

    assert await session.scalar(select(Directory).filter_by(name="test"))

    proc = await asyncio.create_subprocess_exec(
        'ldapdelete',
        '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D', user['sam_accout_name'], '-x', '-w', user['password'],
        dn,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    assert await proc.wait() == 0
    assert not await session.scalar(
        select(Directory).filter_by(name="test"),
    )
