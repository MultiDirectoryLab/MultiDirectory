
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from ldap_protocol.utils import get_base_dn
from models.ldap3 import Directory, Group, Path
from typing import AsyncGenerator


class GroupMemberManagerMixin:
    async def get_groups(
        self,
        dn_list: list[str],
        session,
    ) -> list[Group]:
        """Get dirs with groups by dn list."""
        base_dn = await get_base_dn(session)

        paths = []

        for dn in dn_list:
            dn_is_base = dn.lower() == base_dn.lower()

            if dn_is_base:
                raise AttributeError('Cannot set memberOf with base dn')

            base_obj = dn.lower().removesuffix(
                ',' + base_dn.lower()).split(',')

            paths.append([path for path in reversed(base_obj) if path])

        query = select(   # noqa: ECE001
            Directory)\
            .join(Directory.path)\
            .filter(Path.path.in_(paths))\
            .options(selectinload(Directory.group).selectinload(
                Group.parent_groups).selectinload(
                    Group.directory).selectinload(Directory.path))

        result = await session.stream_scalars(query)

        return [
            directory.group
            async for directory in result
            if directory.group is not None]
