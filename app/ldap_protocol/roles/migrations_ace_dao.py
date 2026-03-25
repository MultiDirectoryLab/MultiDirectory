"""Access control entry DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Sequence

from entities_legacy import AttributeTypeLegacy
from sqlalchemy import Row, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from entities import AccessControlEntry, Directory, EntityType
from enums import EntityTypeNames
from repo.pg.tables import queryable_attr as qa


class AccessControlEntryAttributeTypeRemapDAO:
    """Access control entry DAO."""

    __session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Access Control Entry DAO with a database session."""
        self.__session = session

    async def upgrade(self) -> None:
        ace_rows = await self._get_all_raw_aces_legacy()
        if not ace_rows:
            return

        attribute_names = {row.name for row in ace_rows}
        directory_rows_q = await self.__session.execute(
            select(qa(Directory.name), qa(Directory.id))
            .join(
                EntityType,
                qa(EntityType.id) == qa(Directory.entity_type_id),
            )
            .where(
                qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE,
                qa(Directory.name).in_(attribute_names),
            ),
        )
        directory_by_name = {row.name: row.id for row in directory_rows_q}

        updates = [
            {"ace_id": row.id, "directory_id": directory_by_name[row.name]}
            for row in ace_rows
            if row.name in directory_by_name
        ]
        if not updates:
            return

        for item in updates:
            await self.__session.execute(
                update(AccessControlEntry)
                .where(qa(AccessControlEntry.id) == item["ace_id"])
                .values(attribute_type_id=item["directory_id"]),
            )

    async def _get_all_raw_aces_legacy(self) -> Sequence[Row[tuple[int, str]]]:
        ace_rows_q = await self.__session.execute(
            select(qa(AccessControlEntry.id), qa(AttributeTypeLegacy.name))
            .join(
                AttributeTypeLegacy,
                qa(AccessControlEntry.attribute_type_name)
                == qa(AttributeTypeLegacy.name),
            )
            .where(qa(AccessControlEntry.attribute_type_name).is_not(None)),
        )
        return ace_rows_q.all()

    async def downgrade(self) -> None:
        ace_rows = await self._get_all_raw_aces()
        if not ace_rows:
            return

        attribute_names = {row.name for row in ace_rows}
        legacy_rows_q = await self.__session.execute(
            select(qa(AttributeTypeLegacy.name), qa(AttributeTypeLegacy.id))
            .where(qa(AttributeTypeLegacy.name).in_(attribute_names)),
        )  # fmt: skip
        legacy_by_name = {row.name: row.id for row in legacy_rows_q}

        updates = [
            {"ace_id": row.id, "legacy_id": legacy_by_name[row.name]}
            for row in ace_rows
            if row.name in legacy_by_name
        ]
        if not updates:
            return

        for item in updates:
            await self.__session.execute(
                update(AccessControlEntry)
                .where(qa(AccessControlEntry.id) == item["ace_id"])
                .values(attribute_type_id=item["legacy_id"]),
            )

    async def _get_all_raw_aces(self) -> Sequence[Row[tuple[int, str]]]:
        ace_rows_q = await self.__session.execute(
            select(qa(AccessControlEntry.id), qa(Directory.name))
            .join(
                Directory,
                qa(AccessControlEntry.attribute_type_name)
                == qa(Directory.name),
            )
            .join(
                EntityType,
                qa(EntityType.id) == qa(Directory.entity_type_id),
            )
            .where(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE)
            .where(qa(AccessControlEntry.attribute_type_name).is_not(None)),
        )
        return ace_rows_q.all()
