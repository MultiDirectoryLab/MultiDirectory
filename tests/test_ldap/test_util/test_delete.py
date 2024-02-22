"""Test delete."""

import asyncio
import tempfile

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models.ldap3 import Directory


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_ldap_delete(
        session: AsyncSession, settings: Settings, user: dict) -> None:
    """Test ldapdelete on server."""
    dn = "cn=test,dc=md,dc=test"

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            f"dn: {dn}\n"
            "name: test\n"
            "cn: test\n"
            "objectClass: organization\n"
            "objectClass: top\n"
            "memberOf: cn=domain admins,cn=groups,dc=md,dc=test\n"
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
