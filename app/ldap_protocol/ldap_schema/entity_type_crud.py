"""EntityType utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable

from pydantic import BaseModel, Field
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    PaginationParams,
    PaginationResult,
)
from models import Attribute, Directory, EntityType


class EntityTypeSchema(BaseModel):
    """EntityType Schema."""

    name: str
    is_system: bool
    object_class_names: list[str] = Field([], min_length=1, max_length=10000)

    @classmethod
    def from_db(cls, entity_type: EntityType) -> "EntityTypeSchema":
        """Create an instance of EntityType Schema from database."""
        return cls(
            name=entity_type.name,
            is_system=entity_type.is_system,
            object_class_names=entity_type.object_class_names,
        )


class EntityTypeUpdateSchema(BaseModel):
    """EntityType Schema for modify/update."""

    name: str
    object_class_names: list[str] = Field([], min_length=1, max_length=10000)


class EntityTypePaginationSchema(BasePaginationSchema[EntityTypeSchema]):
    """EntityType Schema with pagination result."""

    items: list[EntityTypeSchema]


class EntityTypeDAO:
    """EntityType manager."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize EntityTypeDAO with a database session."""
        self._session = session

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated EntityTypes.

        :param PaginationParams params: page_size and page_number.
        :return PaginationResult: Chunk of EntityTypes and metadata.
        """
        return await PaginationResult[EntityType].get(
            params=params,
            query=select(EntityType).order_by(EntityType.id),
            sqla_model=EntityType,
            session=self._session,
        )

    async def create_one(
        self,
        name: str,
        object_class_names: Iterable[str],
        is_system: bool,
    ) -> None:
        """Create a new EntityType.

        :param str name: Name.
        :param Iterable[str] object_class_names: Object Class names.
        :param bool is_system: Is system.
        :return None.
        """
        entity_type = EntityType(
            name=name,
            object_class_names=object_class_names,
            is_system=is_system,
        )
        self._session.add(entity_type)

    async def get_one_by_name(
        self,
        entity_type_name: str,
    ) -> EntityType | None:
        """Get single EntityType by name.

        :param str entity_type_name: EntityType name.
        :return EntityType | None: Instance of EntityType.
        """
        return await self._session.scalar(
            select(EntityType)
            .where(EntityType.name == entity_type_name)
        )  # fmt: skip

    async def get_entity_type_by_object_class_names(
        self,
        object_class_names: Iterable[str],
    ) -> EntityType | None:
        """Get single EntityType by object class names.

        :param Iterable[str] object_class_names: object class names.
        :return EntityType | None: EntityType.
        """
        result = await self._session.execute(
            select(EntityType)
            .where(
                EntityType.object_class_names.contains(object_class_names),
                EntityType.object_class_names.contained_by(object_class_names)
            )
        )  # fmt: skip

        return result.scalar_one_or_none()

    async def modify_one(
        self,
        entity_type: EntityType,
        new_statement: EntityTypeUpdateSchema,
    ) -> None:
        """Modify EntityType.

        :param EntityType entity_type: EntityType.
        :param EntityTypeUpdateSchema new_statement: New statement\
            of entity type.
        :return None.
        """
        entity_type.name = new_statement.name
        entity_type.object_class_names = new_statement.object_class_names

        result = await self._session.execute(
            select(Directory)
            .where(Directory.entity_type_id == entity_type.id)
            .options(selectinload(Directory.attributes))
        )  # fmt: skip

        for directory in result.scalars():
            await self._session.execute(
                delete(Attribute)
                .where(
                    Attribute.directory == directory,
                    or_(
                        Attribute.name == "objectclass",
                        Attribute.name == "objectClass"
                    ),
                )
            )  # fmt: skip

            for object_class_name in entity_type.object_class_names:
                self._session.add(
                    Attribute(
                        directory=directory,
                        value=object_class_name,
                        name="objectClass",
                    )
                )

    async def delete_all_by_names(
        self,
        entity_type_names: list[str],
    ) -> None:
        """Delete not system and not used EntityType by Names.

        :param list[str] entity_type_names: EntityType names.
        :return None.
        """
        await self._session.execute(
            delete(EntityType)
            .where(
                EntityType.name.in_(entity_type_names),
                EntityType.is_system.is_(False),
                EntityType.id.notin_(
                    select(Directory.entity_type_id)
                    .where(Directory.entity_type_id.isnot(None))
                ),
            ),
        )  # fmt: skip

    async def attach_entity_type_to_directories(self) -> None:
        """Find all directories without an entity type and attach it to them.

        :return None.
        """
        result = await self._session.execute(
            select(Directory)
            .where(Directory.entity_type_id.is_(None))
            .options(
                selectinload(Directory.attributes),
                selectinload(Directory.entity_type),
            )
        )

        for directory in result.scalars():
            await self.attach_entity_type_to_directory(
                directory=directory,
                is_system_entity_type=False,
            )

        return None

    async def attach_entity_type_to_directory(
        self,
        directory: Directory,
        is_system_entity_type: bool,
    ) -> None:
        """Try to find the EntityType, attach this EntityType to the Directory.

        :param Directory directory: Directory to attach entity type.
        :param bool is_system_entity_type: Is system entity type.
        :return None.
        """
        object_class_names = directory.object_class_names_set

        entity_type = await self.get_entity_type_by_object_class_names(
            object_class_names
        )
        if not entity_type:
            entity_type_name = EntityType.generate_entity_type_name(
                directory=directory
            )
            await self.create_one(
                name=entity_type_name,
                object_class_names=object_class_names,
                is_system=is_system_entity_type,
            )
            await self._session.flush()
            await self.get_one_by_name(entity_type_name)

        directory.entity_type = entity_type
