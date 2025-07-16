"""Entity Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable

from pydantic import BaseModel, Field
from sqlalchemy import delete, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.exceptions import InstanceNotFoundError
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    PaginationParams,
    PaginationResult,
    build_paginated_search_query,
)
from models import Attribute, Directory, EntityType


class EntityTypeSchema(BaseModel):
    """Entity Type Schema."""

    name: str
    is_system: bool
    object_class_names: list[str] = Field([], min_length=1, max_length=10000)


class EntityTypeUpdateSchema(BaseModel):
    """Entity Type Schema for modify/update."""

    name: str
    object_class_names: list[str] = Field([], min_length=1, max_length=10000)


class EntityTypePaginationSchema(BasePaginationSchema[EntityTypeSchema]):
    """Entity Type Schema with pagination result."""

    items: list[EntityTypeSchema]


class EntityTypeDAO:
    """Entity Type DAO."""

    __session: AsyncSession
    __object_class_dao: ObjectClassDAO
    EntityTypeNotFoundError = InstanceNotFoundError

    def __init__(
        self,
        session: AsyncSession,
        object_class_dao: ObjectClassDAO,
    ) -> None:
        """Initialize Entity Type DAO with a database session."""
        self.__session = session
        self.__object_class_dao = object_class_dao

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated Entity Types.

        :param PaginationParams params: page_size and page_number.
        :return PaginationResult: Chunk of Entity Types and metadata.
        """
        query = build_paginated_search_query(
            model=EntityType,
            order_by_field=EntityType.name,
            params=params,
            search_field=EntityType.name,
        )

        return await PaginationResult[EntityType].get(
            params=params,
            query=query,
            session=self.__session,
        )

    async def create_one(
        self,
        name: str,
        object_class_names: Iterable[str],
        is_system: bool,
    ) -> None:
        """Create a new Entity Type instance.

        :param str name: Name.
        :param Iterable[str] object_class_names: Object Class names.
        :param bool is_system: Is system.
        :return None.
        """
        entity_type = EntityType(
            name=name,
            object_class_names=sorted(set(object_class_names)),
            is_system=is_system,
        )
        self.__session.add(entity_type)

    async def get_one_by_name(
        self,
        entity_type_name: str,
    ) -> EntityType:
        """Get single Entity Type by name.

        :param str entity_type_name: Entity Type name.
        :raise EntityTypeNotFoundError: If Entity Type not found.
        :return EntityType: Instance of Entity Type.
        """
        entity_type = await self.__session.scalar(
            select(EntityType)
            .where(EntityType.name == entity_type_name)
        )  # fmt: skip

        if not entity_type:
            raise self.EntityTypeNotFoundError(
                f"Entity Type with name '{entity_type_name}' not found."
            )

        return entity_type

    async def get_entity_type_by_object_class_names(
        self,
        object_class_names: Iterable[str],
    ) -> EntityType | None:
        """Get single Entity Type by object class names.

        :param Iterable[str] object_class_names: object class names.
        :return EntityType | None: Instance of Entity Type or None.
        """
        result = await self.__session.execute(
            select(EntityType)
            .where(
                EntityType.object_class_names.contains(object_class_names),
                EntityType.object_class_names.contained_by(object_class_names)
            )
        )  # fmt: skip

        return result.scalars().first()

    async def modify_one(
        self,
        entity_type: EntityType,
        new_statement: EntityTypeUpdateSchema,
        object_class_dao: ObjectClassDAO,
    ) -> None:
        """Modify Entity Type.

        :param EntityType entity_type: Entity Type.
        :param EntityTypeUpdateSchema new_statement: New statement\
            of Entity Type.
        :return None.
        """
        await object_class_dao.is_all_object_classes_exists(
            new_statement.object_class_names
        )

        entity_type.name = new_statement.name
        entity_type.object_class_names = new_statement.object_class_names

        result = await self.__session.execute(
            select(Directory)
            .join(Directory.entity_type)
            .where(EntityType.name == entity_type.name)
            .options(selectinload(Directory.attributes))
        )  # fmt: skip

        for directory in result.scalars():
            await self.__session.execute(
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
                self.__session.add(
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

        :param list[str] entity_type_names: Entity Type names.
        :return None.
        """
        await self.__session.execute(
            delete(EntityType).where(
                EntityType.name.in_(entity_type_names),
                EntityType.is_system.is_(False),
                EntityType.id.not_in(
                    select(Directory.entity_type_id)
                    .where(Directory.entity_type_id.isnot(None))
                ),
            )
        )  # fmt: skip

    async def attach_entity_type_to_directories(self) -> None:
        """Find all Directories without an Entity Type and attach it to them.

        :return None.
        """
        result = await self.__session.execute(
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
        """Try to find the Entity Type, attach it to the Directory.

        :param Directory directory: Directory to attach Entity Type.
        :param bool is_system_entity_type: Is system Entity Type.
        :param ObjectClassDAO object_class_dao: Object Class DAO.
        :return None.
        """
        object_class_names = directory.object_class_names_set

        await self.__object_class_dao.is_all_object_classes_exists(
            object_class_names
        )

        entity_type = await self.get_entity_type_by_object_class_names(
            object_class_names
        )
        if not entity_type:
            entity_type_name = EntityType.generate_entity_type_name(
                directory=directory
            )
            try:
                await self.create_one(
                    name=entity_type_name,
                    object_class_names=object_class_names,
                    is_system=is_system_entity_type,
                )
                await self.__session.flush()
            except IntegrityError:
                # NOTE: This happens when Race Condition occurs.
                # If the Entity Type already exists, we can ignore the error.
                pass

            entity_type = await self.get_entity_type_by_object_class_names(
                object_class_names
            )

        directory.entity_type = entity_type
