"""Access Control Entry Gateway."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from entities import AccessControlEntry
from enums import AceType

from .tables import ace_directory_memberships_table, queryable_attr as qa


class AccessControlEntryGateway:

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(
        self,
        directory_id: int,
        role_ids: list[int],
        ace_types: list[AceType],
        load_attribute_type: bool = False,
        requeire_attribute_type_null: bool = False,
    ) -> list[AccessControlEntry]:
        query = (
            select(AccessControlEntry)
            .join(
                ace_directory_memberships_table,
                qa(AccessControlEntry.id)
                == ace_directory_memberships_table.c.access_control_entry_id,
            )
            .where(
                ace_directory_memberships_table.c.directory_id == directory_id,
                qa(AccessControlEntry.role_id).in_(role_ids),
                qa(AccessControlEntry.ace_type).in_(ace_types),
            )
        )
        if load_attribute_type:
            query = query.options(
                joinedload(qa(AccessControlEntry.attribute_type)),
            )

        if requeire_attribute_type_null:
            query = query.where(
                qa(AccessControlEntry.attribute_type_id).is_(None),
            )

        return list((await self._session.scalars(query)).all())
