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
from itertools import chain

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from config import Settings
from models.database import create_session_factory
from models.ldap3 import (
    Attribute,
    CatalogueSetting,
    Directory,
    Group,
    GroupMembership,
    NetworkPolicy,
    User,
    UserMembership,
)
from security import get_password_hash

from .dev_data import DATA


async def _get_group(name: str, session: AsyncSession) -> list[Group]:
    return await session.scalar(
        select(Group).join(Group.directory).filter(
            Directory.name == name,
            Directory.object_class == 'group',
        ).options(selectinload(Group.child_groups)))


async def _create_dir(
    data: dict,
    session: AsyncSession,
    parent: Directory | None = None,
) -> None:
    """Create data recursively."""
    if not parent:
        dir_ = Directory(
            object_class=data['object_class'], name=data['name'])
        path = dir_.create_path(dn=dir_.get_dn_prefix())

        async with session.begin_nested():
            session.add_all([dir_, path])
            dir_.paths.append(path)
            dir_.depth = len(path.path)

    else:
        dir_ = Directory(
            object_class=data['object_class'],
            name=data['name'],
            parent=parent)
        path = dir_.create_path(parent, dir_.get_dn_prefix())

        async with session.begin_nested():
            session.add_all([dir_, path])
            path.directories.extend(
                [p.endpoint for p in parent.paths + [path]])
            dir_.depth = len(path.path)

    if dir_.object_class == 'group':
        group = Group(directory=dir_)
        session.add(group)
        for group_name in data.get('groups', []):
            parent_group: Group = await _get_group(group_name, session)
            session.add(GroupMembership(
                group_id=parent_group.id, group_child_id=group.id))

    if "attributes" in data:
        attrs = chain(
            data["attributes"].items(),
            [('objectClass', [dir_.object_class])])

        for name, values in attrs:
            for value in values:
                session.add(Attribute(
                    directory=dir_,
                    name=name,
                    value=value if isinstance(value, str) else None,
                    bvalue=value if isinstance(value, bytes) else None,
                ))

    if 'organizationalPerson' in data:
        user_data = data['organizationalPerson']
        user = User(
            directory=dir_,
            sam_accout_name=user_data['sam_accout_name'],
            user_principal_name=user_data['user_principal_name'],
            display_name=user_data['display_name'],
            mail=user_data['mail'],
            password=get_password_hash(user_data['password']),
        )
        session.add(user)
        await session.flush()
        session.add(Attribute(
            directory=dir_,
            name='homeDirectory',
            value=f"/home/{user.uid}"))

        for group_name in user_data.get('groups', []):
            parent_group = await _get_group(group_name, session)
            await session.flush()
            session.add(UserMembership(
                group_id=parent_group.id, user_id=user.id))

    await session.flush()

    if 'children' in data:
        for n_data in data['children']:
            await _create_dir(n_data, session, dir_)


async def setup_enviroment(
        session: AsyncSession, *,
        data: list, dn: str = "multifactor.dev") -> None:
    """Create directories and users for enviroment."""
    cat_result = await session.execute(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == 'defaultNamingContext'),
    )
    if cat_result.scalar():
        logger.warning('dev data already set up')
        return

    catalogue = CatalogueSetting(
        name='defaultNamingContext', value=dn)

    async with session.begin_nested():
        session.add(catalogue)
        session.add(NetworkPolicy(
            name='Default open policy',
            netmasks=['0.0.0.0/0'],
            raw=['0.0.0.0/0'],
            priority=1,
        ))

    try:
        for unit in data:
            await _create_dir(unit, session)
    except Exception:
        import traceback
        logger.error(traceback.format_exc())  # noqa
        raise


if __name__ == '__main__':
    AsyncSessionFactory = create_session_factory(Settings())

    async def execute() -> None:  # noqa
        async with AsyncSessionFactory() as session:
            await setup_enviroment(session, data=DATA)
            await session.commit()

    asyncio.run(execute())
