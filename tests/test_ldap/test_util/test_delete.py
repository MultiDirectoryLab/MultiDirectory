"""Test delete.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import tempfile

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.policies.access_policy import create_access_policy
from models import Directory
from tests.conftest import TestCreds


@pytest.mark.asyncio
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
            '-vvv', '-H', f'ldap://{settings.HOST}:{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        assert await proc.wait() == 0

    assert await session.scalar(select(Directory).filter_by(name="test"))

    proc = await asyncio.create_subprocess_exec(
        'ldapdelete',
        '-vvv', '-H', f'ldap://{settings.HOST}:{settings.PORT}',
        '-D', user['sam_accout_name'], '-x', '-w', user['password'],
        dn,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    assert await proc.wait() == 0
    assert not await session.scalar(
        select(Directory).filter_by(name="test"),
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
async def test_ldap_delete_w_access_control(
        session: AsyncSession, settings: Settings, creds: TestCreds) -> None:
    """Test ldapadd on server."""
    dn = 'cn=test,dc=md,dc=test'

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            f"dn: {dn}\n"
            "name: test\n"
            "cn: test\n"
            "objectClass: organization\n"
            "objectClass: top\n"
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(  # Add as Admin
            'ldapadd',
            '-vvv', '-H', f'ldap://{settings.HOST}:{settings.PORT}',
            '-D', creds.un, '-x', '-w', creds.pw,
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        assert await proc.wait() == LDAPCodes.SUCCESS

    async def try_delete() -> int:
        proc = await asyncio.create_subprocess_exec(
            'ldapdelete',
            '-vvv', '-H', f'ldap://{settings.HOST}:{settings.PORT}',
            '-D', "user_non_admin", '-x', '-w', creds.pw,
            dn,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        return await proc.wait()

    assert await try_delete() == LDAPCodes.NO_SUCH_OBJECT

    await create_access_policy(
        name='TEST Read Access Policy',
        can_add=False,
        can_modify=False,
        can_read=True,
        can_delete=False,
        grant_dn=dn,
        groups=["cn=domain users,cn=groups,dc=md,dc=test"],
        session=session,
    )

    assert await try_delete() == LDAPCodes.INSUFFICIENT_ACCESS_RIGHTS

    await create_access_policy(
        name='TEST Del Access Policy',
        can_add=False,
        can_modify=False,
        can_read=True,
        can_delete=True,
        grant_dn=dn,
        groups=["cn=domain users,cn=groups,dc=md,dc=test"],
        session=session,
    )

    assert await try_delete() == LDAPCodes.SUCCESS

    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-x', '-H', f'ldap://{settings.HOST}:{settings.PORT}',
        '-D', 'user_non_admin',
        '-w', creds.pw,
        '-b', 'dc=md,dc=test', 'objectclass=*',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split('\n')
    result = await proc.wait()

    dn_list = [d.removeprefix("dn: ") for d in data if d.startswith('dn:')]

    assert result == 0
    assert dn not in dn_list
