import asyncio

from models.database import async_session
from models.ldap3 import Directory, Path

loop = asyncio.new_event_loop()


async def main():
    async with async_session() as session:
        async with session.begin():
            d1 = Directory(object_class='organizationUnit', name='Users')
            p = Path(
                path=[f"{d1.get_dn()}={d1.name}"],
                endpoint=d1)
            session.add_all([d1, p])
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

loop.run_until_complete(main())
