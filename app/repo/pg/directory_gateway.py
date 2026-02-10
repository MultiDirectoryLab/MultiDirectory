"""Directory Gateway module."""

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from entities import Attribute, Directory, Group
from ldap_protocol.utils.queries import get_filter_from_path

from .tables import queryable_attr as qa


class DirectoryGateway:

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_dn(self, dn: str) -> Directory | None:
        query = (
            select(Directory)
            .options(
                joinedload(qa(Directory.entity_type)),
                joinedload(qa(Directory.user)),
                selectinload(qa(Directory.groups)).selectinload(
                    qa(Group.directory),
                ),
                joinedload(qa(Directory.group)).selectinload(
                    qa(Group.members),
                ),
                selectinload(qa(Directory.attributes)),
            )
            .filter(get_filter_from_path(dn))
        )
        return await self._session.scalar(query)

    async def delete(self, directory: Directory) -> None:
        await self._session.delete(directory)

    async def has_primary_group_members(self, directory_id: int) -> bool:
        query = exists(Attribute).where(
            qa(Attribute.name) == "primaryGroupID",
            qa(Attribute.value) == directory_id,
        )
        return bool(await self._session.scalar(select(query)))

    async def commit(self) -> None:
        await self._session.commit()
