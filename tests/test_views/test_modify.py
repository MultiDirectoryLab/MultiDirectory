"""Test modify protocol."""

import asyncio
import tempfile
from collections import defaultdict

import pytest
from sqlalchemy import select
from sqlalchemy.orm import joinedload, subqueryload

from app.extra import TEST_DATA, setup_enviroment
from app.models.ldap3 import Directory, Path


@pytest.mark.asyncio()
async def test_ldap_base_modify(session, settings):
    """Test ldapadd on server."""
    await setup_enviroment(session, dn="multidurectory.test", data=TEST_DATA)
    await session.commit()

    user = TEST_DATA[1]['children'][0]['organizationalPerson']

    dn = "cn=user0,ou=users,dc=multidurectory,dc=test"

    query = select(Directory)\
        .options(
            subqueryload(Directory.attributes),
            joinedload(Directory.user))\
        .join(Directory.path).filter(Path.path == ["ou=users", "cn=user0"])

    directory = await session.scalar(query)
    assert directory.user.mail == "user0@mail.com"

    attributes = defaultdict(list)

    for attr in directory.attributes:
        attributes[attr.name].append(attr.value)

    assert 'user' in attributes['objectClass']
    assert attributes['posixEmail'] == ["abctest@mail.com"]

    with tempfile.NamedTemporaryFile("w") as file:
        file.write((
            f"dn: {dn}\n"
            "changetype: modify\n"
            "replace: mail\n"
            "mail: modme@student.of.life.edu\n"
            "-\n"
            "add: title\n"
            "title: Grand Poobah\n"
            "title: Grand Poobah1\n"
            "title: Grand Poobah2\n"
            "title: Grand Poobah3\n"
            "-\n"
            "add: jpegPhoto\n"
            "jpegPhoto: modme.jpeg\n"
            "-\n"
            "delete: posixEmail\n"
            "-\n"
        ))
        file.seek(0)
        proc = await asyncio.create_subprocess_exec(
            'ldapmodify',
            '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
            '-D', user['sam_accout_name'], '-x', '-w', user['password'],
            '-f', file.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        result = await proc.wait()

    assert result == 0
    await session.refresh(directory)

    attributes = defaultdict(list)

    for attr in directory.attributes:
        attributes[attr.name].append(attr.value)

    assert attributes['objectClass'] == [
        'top', 'person',
        'organizationalPerson', 'posixAccount', 'user']
    assert attributes['title'] == [
        "Grand Poobah", "Grand Poobah1",
        "Grand Poobah2", "Grand Poobah3",
    ]
    assert attributes['jpegPhoto'] == ['modme.jpeg']
    assert directory.user.mail == "modme@student.of.life.edu"

    assert 'posixEmail' not in attributes
