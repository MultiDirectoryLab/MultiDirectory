"""Entity Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable

from pydantic import BaseModel, Field
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.exceptions import InstanceNotFoundError
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    PaginationParams,
    PaginationResult,
)
from models import Attribute, Directory, EntityType


class EntityTypeSchema(BaseModel):
    """Entity Type Schema."""

    name: str
    is_system: bool
    object_class_names: list[str] = Field([], min_length=1, max_length=10000)

    @classmethod
    def from_db(cls, entity_type: EntityType) -> "EntityTypeSchema":
        """Create an instance of Entity Type Schema from SQLA object.

        Returns:
            EntityTypeSchema: Instance of Entity Type Schema.
        """
        return cls(
            name=entity_type.name,
            is_system=entity_type.is_system,
            object_class_names=entity_type.object_class_names,
        )


class EntityTypeUpdateSchema(BaseModel):
    """Entity Type Schema for modify/update."""

    name: str
    object_class_names: list[str] = Field([], min_length=1, max_length=10000)


class EntityTypePaginationSchema(BasePaginationSchema[EntityTypeSchema]):
    """Entity Type Schema with pagination result."""

    items: list[EntityTypeSchema]


class EntityTypeDAO:
    """Entity Type DAO."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Entity Type DAO with a database session."""
        self._session = session

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated Entity Types.

        Returns:
            PaginationResult: Chunk of Entity Types and metadata.
        """
        return await PaginationResult[EntityType].get(
            params=params,
            query=select(EntityType).order_by(EntityType.name),
            sqla_model=EntityType,
            session=self._session,
        )

    async def create_one(
        self,
        name: str,
        object_class_names: Iterable[str],
        is_system: bool,
    ) -> None:
        """Create a new Entity Type instance.

        Args:
            name (str): Name.
            object_class_names (Iterable[str]): Object Class names.
            is_system (bool): Is system.
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
    ) -> EntityType:
        """Get single Entity Type by name.

        Returns:
            EntityType: Instance of Entity Type.

        Raises:
            InstanceNotFoundError: If Entity Type not found.
        """
        entity_type = await self._session.scalar(
            select(EntityType)
            .where(EntityType.name == entity_type_name)
        )  # fmt: skip

        if not entity_type:
            raise InstanceNotFoundError(
                f"Entity Type with name '{entity_type_name}' not found."
            )

        return entity_type

    async def get_entity_type_by_object_class_names(
        self,
        object_class_names: Iterable[str],
    ) -> EntityType | None:
        """Get single Entity Type by object class names.

        Returns:
            EntityType | None: Instance of Entity Type or None.
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
        object_class_dao: ObjectClassDAO,
    ) -> None:
        """Modify Entity Type.

        Args:
            entity_type (EntityType): Entity Type.
            new_statement (EntityTypeUpdateSchema): New statement\
                of Entity Type.
            object_class_dao (ObjectClassDAO): Object Class DAO.
        """
        await object_class_dao.is_all_object_classes_exists(
            new_statement.object_class_names
        )

        entity_type.name = new_statement.name
        entity_type.object_class_names = new_statement.object_class_names

        result = await self._session.execute(
            select(Directory)
            .where(Directory.entity_type_name == entity_type.name)
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
        """Delete not system and not used Entity Type by their names.

        Args:
            entity_type_names (list[str]): Entity Type names.
        """
        await self._session.execute(
            delete(EntityType)
            .where(
                EntityType.name.in_(entity_type_names),
                EntityType.is_system.is_(False),
                EntityType.name.notin_(
                    select(Directory.entity_type_name)
                    .where(Directory.entity_type_name.isnot(None))
                ),
            ),
        )  # fmt: skip

    async def attach_entity_type_to_directories(self) -> None:
        """Find all Directories without Entity Type and attach it to them."""
        result = await self._session.execute(
            select(Directory)
            .where(Directory.entity_type_name.is_(None))
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

        return

    async def attach_entity_type_to_directory(
        self,
        directory: Directory,
        is_system_entity_type: bool,
    ) -> None:
        """Try to find the Entity Type, attach it to the Directory.

        Args:
            directory (Directory): Directory to attach Entity Type.
            is_system_entity_type (bool): Is system Entity Type.
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
            entity_type = await self.get_one_by_name(entity_type_name)

        directory.entity_type = entity_type
