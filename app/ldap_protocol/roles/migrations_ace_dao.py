"""Access control entry DAO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from enums import EntityTypeNames


class AccessControlEntryAttributeTypeRemapDAO:
    """Access control entry DAO."""

    __session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Access Control Entry DAO with a database session."""
        self.__session = session

    async def upgrade(self) -> None:
        await self.__session.execute(
            text(
                """
                UPDATE "AccessControlEntries" AS ace
                  SET "attributeTypeId" = directory.id
                FROM "AttributeTypes" AS attribute_type
                  JOIN "Directory" AS directory ON directory.name = attribute_type.name
                  JOIN "EntityTypes" AS entity_type ON entity_type.id = directory.entity_type_id

                WHERE
                  ace."attributeTypeId" = attribute_type.id
                  AND entity_type.name = :attribute_type_entity_name
                """,  # noqa: E501
            ),
            {"attribute_type_entity_name": EntityTypeNames.ATTRIBUTE_TYPE},
        )
        await self.__session.execute(
            text(
                """
                UPDATE "AccessControlEntries" AS ace
                  SET "attributeTypeId" = NULL
                WHERE
                  ace."attributeTypeId" IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1
                      FROM "Directory" AS directory
                      WHERE directory.id = ace."attributeTypeId"
                  )
                """,
            ),
        )

    async def downgrade(self) -> None:
        await self.__session.execute(
            text(
                """
                UPDATE "AccessControlEntries" AS ace
                  SET "attributeTypeId" = attribute_type.id
                FROM "Directory" AS directory
                  JOIN "EntityTypes" AS entity_type ON entity_type.id = directory.entity_type_id
                  JOIN "AttributeTypes" AS attribute_type ON attribute_type.name = directory.name

                WHERE
                  ace."attributeTypeId" = directory.id
                  AND entity_type.name = :attribute_type_entity_name
                """,  # noqa: E501
            ),
            {"attribute_type_entity_name": EntityTypeNames.ATTRIBUTE_TYPE},
        )
        await self.__session.execute(
            text(
                """
                UPDATE "AccessControlEntries" AS ace
                  SET "attributeTypeId" = NULL
                WHERE
                  ace."attributeTypeId" IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1
                      FROM "AttributeTypes" AS attribute_type
                      WHERE attribute_type.id = ace."attributeTypeId"
                  )
                """,
            ),
        )
