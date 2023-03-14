"""Dev data creation.

DC=multifactor
  OU=IT
    CN=User 1
    CN=User 2
  CN=Users
    CN=User 3
    CN=User 4
  OU="2FA"
    CN=Service Accounts
      CN=User 5
"""
import asyncio

from loguru import logger
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from models.database import AsyncSession, async_session
from models.ldap3 import (
    Attribute,
    CatalogueSetting,
    Directory,
    Group,
    GroupMembership,
    User,
    UserMembership,
)

DATA = [  # noqa
    {
        "name": "groups",
        "object_class": "group",
        "attributes": {
            "objectClass": ["top"],
            'groupType': ['-2147483646'],
            'instanceType': ['4'],
            'objectGUID': ['{9aac5c3d-689f-4557-806a-f123ed6bb230}'],
            'objectSid': ['S-1-5-21-625588008-872595822-1771925161-6007'],
            'sAMAccountName': ['groups'],
            'sAMAccountType': ['268435456'],
        },
        "children": [
            {"name": "administrators", "object_class": "group",
                "attributes": {"objectClass": ["top"]}},
            {"name": "committers", "object_class": "group",
                "attributes": {"objectClass": ["top"]}},
            {"name": "operators", "object_class": "group",
                "attributes": {"objectClass": ["top"]}},
            {"name": "guests", "object_class": "group", 'groups': [
                "operators", 'committers']},
        ],
    },
    {
        "name": "it",
        "object_class": "organizationalUnit",
        "attributes": {"objectClass": ["top", "container"]},
        "children": [
            {
                "name": "user 1",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_accout_name": "username1",
                    "user_principal_name": "username1@multifactor.dev",
                    "mail": "username1@multifactor.dev",
                    "display_name": "User 1",
                    "password": "password",
                    "groups": ['administrators', 'operators'],
                },
                "attributes": {"objectClass": [
                    "top", "person", "organizationalPerson"]},
            },
            {
                "name": "user 2",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_accout_name": "username2",
                    "user_principal_name": "username2@multifactor.dev",
                    "mail": "username2@multifactor.dev",
                    "display_name": "User 2",
                    "password": "password",
                    "groups": ['administrators', 'operators']
                },
                "attributes": {"objectClass": [
                    "top", "person", "organizationalPerson"]},
            },
        ],
    },
    {
        "name": "users",
        "object_class": "organizationalUnit",
        "attributes": {"objectClass": ["top", "container"]},
        "children": [
            {
                "name": "user 3",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_accout_name": "username3",
                    "user_principal_name": "username3@multifactor.dev",
                    "mail": "username3@multifactor.dev",
                    "display_name": "User 3",
                    "password": "password",
                    "groups": ["operators", "guests"]
                },
                "attributes": {"objectClass": [
                    "top", "person", "organizationalPerson"]},
            },
            {
                "name": "user 4",
                "object_class": "user",
                "organizationalPerson": {
                    "sam_accout_name": "username4",
                    "user_principal_name": "username4@multifactor.dev",
                    "mail": "username4@multifactor.dev",
                    "display_name": "User 4",
                    "password": "password",
                    "groups": ["guests"]
                },
                "attributes": {"objectClass": [
                    "top", "person", "organizationalPerson"]},
            },
        ],
    },
    {
        "name": "2fa",
        "object_class": "organizationalUnit",
        "attributes": {"objectClass": ["top", "container"]},
        "children": [
            {
                "name": "service accounts",
                "object_class": "organizationalUnit",
                "attributes": {"objectClass": ["top", "container"]},
                "children": [
                    {
                        "name": "user 5",
                        "object_class": "user", "organizationalPerson": {
                            "sam_accout_name": "username5",
                            "user_principal_name": "username5@multifactor.dev",
                            "mail": "username5@multifactor.dev",
                            "display_name": "User 5",
                            "password": "password",
                        },
                        "attributes": {"objectClass": [
                            "top", "person", "organizationalPerson"]},
                    },
                ],
            },
        ],
    },
]


async def get_group(name, session):
    return await session.scalar(
        select(Group).join(Group.directory).filter(
            Directory.name == name,
            Directory.object_class == 'group',
        ).options(
            selectinload(Group.child_groups))
    )


async def create_dir(
        data, session: AsyncSession, parent: Directory | None = None):
    """Create data recursively."""
    if not parent:
        dir_ = Directory(
            object_class=data['object_class'], name=data['name'])
        path = dir_.create_path()

        async with session.begin_nested():
            logger.debug(f"creating {dir_.object_class}:{dir_.name}")
            session.add_all([dir_, path])
            dir_.paths.append(path)

    else:
        dir_ = Directory(
            object_class=data['object_class'],
            name=data['name'],
            parent=parent)
        path = dir_.create_path(parent)

        async with session.begin_nested():
            logger.debug(
                f"creating {dir_.object_class}:{dir_.name}:{dir_.parent.id}")
            session.add_all([dir_, path])
            path.directories.extend(
                [p.endpoint for p in parent.paths + [path]])

    if dir_.object_class == 'group':
        group = Group(directory=dir_)
        session.add(group)
        session.commit()
        for group_name in data.get('groups', []):
            parent_group = await get_group(group_name, session)
            session.add(GroupMembership(
                group_id=parent_group.id, group_child_id=group.id))

    if "attributes" in data:
        attrs = data["attributes"]
        for name, values in attrs.items():
            for value in values:
                session.add(Attribute(directory=dir_, name=name, value=value))

    if 'organizationalPerson' in data:
        user_data = data['organizationalPerson']
        user = User(
            directory=dir_,
            sam_accout_name=user_data['sam_accout_name'],
            user_principal_name=user_data['user_principal_name'],
            display_name=user_data['display_name'],
            mail=user_data['mail'],
            password=user_data['password'],
        )
        session.add(user)

        for group_name in user_data.get('groups', []):
            parent_group = await get_group(group_name, session)
            session.add(UserMembership(
                group_id=parent_group.id, user_id=user.id))

    await session.commit()

    if 'children' in data:
        for n_data in data['children']:
            await create_dir(n_data, session, dir_)


async def setup_dev_enviroment() -> None:
    """Create directories and users for development enviroment."""
    async with async_session() as session:
        cat_result = await session.execute(
            select(CatalogueSetting)
            .filter(CatalogueSetting.name == 'defaultNamingContext')
        )
        if cat_result.scalar():
            logger.warning('dev data already set up')
            return

        catalogue = CatalogueSetting(
            name='defaultNamingContext', value='multifactor.dev')

        async with session.begin_nested():
            session.add(catalogue)
        await session.commit()

    async with async_session() as session:
        try:
            for data in DATA:
                await create_dir(data, session)
        except Exception:
            import traceback
            logger.error(traceback.format_exc())  # noqa


if __name__ == '__main__':
    asyncio.run(setup_dev_enviroment())
