"""Test add protocol."""

import asyncio
import tempfile
from collections import defaultdict

import pytest
from sqlalchemy import select
from sqlalchemy.orm import subqueryload

from app.extra import TEST_DATA, setup_enviroment
from app.models.ldap3 import Directory, Path


@pytest.mark.asyncio()
async def test_ldap_root_add(session, settings):
    """Test ldapadd on server."""
    await setup_enviroment(session, dn="multidurectory.test", data=TEST_DATA)
    await session.commit()

    user = TEST_DATA[1]['children'][0]['organizationalPerson']

    dn = "cn=test,dc=multidurectory,dc=test"

    with tempfile.NamedTemporaryFile("w") as file:
        file.write(
            f"dn: {dn}\n"
            "name: test\n"
            "cn: test\n"
            "objectClass: organization\n"
            "objectClass: top\n",
        )
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapadd',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        result = await proc.wait()

    assert result == 0

    query = select(Directory)\
        .options(subqueryload(Directory.attributes))\
        .join(Directory.path).filter(Path.path == ["cn=test"])
    new_dir = await session.scalar(query)

    assert new_dir.name == "test"

    attributes = defaultdict(list)

    for attr in new_dir.attributes:
        attributes[attr.name].append(attr.value)

    assert attributes['objectClass'] == ['organization', 'top']
