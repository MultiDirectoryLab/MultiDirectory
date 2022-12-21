"""Extra scripts for interacting with models."""

import asyncio

from models.database import async_session
from models.ldap3 import CatalogueSetting, Directory, Path, User

loop = asyncio.new_event_loop()


async def main():
    async with async_session() as session:
        async with session.begin():
            s = CatalogueSetting(
                name='defaultNamingContext', value='multifactor.local')
            d1 = Directory(object_class='organizationUnit', name='Users')
            p = Path(
                path=[f"{d1.get_dn()}={d1.name}"],
                endpoint=d1)
            session.add_all([d1, p, s])
            d1.paths.append(p)
        await session.commit()

    async with async_session() as session:
        async with session.begin():

            d2 = Directory(object_class='User', name='FooUser', parent=d1)
            p2 = Path(
                path=d1.path.path + [f"{d2.get_dn()}={d2.name}"],
                endpoint=d2)

            session.add_all([d2, p2])
            d2.paths.extend(d1.paths + [p2])
            print(p2.directories)

            session.add(User(
                directory=d2,
                sam_accout_name='username',
                user_principal_name='username@multifactor.local',
                display_name='FooUser',
                password='password',
            ))

loop.run_until_complete(main())
