"""Entity Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable

from adaptix.conversion import get_converter
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from abstract_dao import AbstractDAO
from constants import PRIMARY_ENTITY_TYPE_NAMES
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.exceptions import (
    EntityTypeAlreadyExistsError,
    EntityTypeCantModifyError,
    EntityTypeNotFoundError,
)
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import (
    PaginationParams,
    PaginationResult,
    build_paginated_search_query,
)
from models import Attribute, Directory, EntityType, ObjectClass

_convert = get_converter(EntityType, EntityTypeDTO)


class EntityTypeDAO(AbstractDAO[EntityTypeDTO]):
    """Entity Type DAO."""

    __session: AsyncSession
    __object_class_dao: ObjectClassDAO

    def __init__(
        self,
        session: AsyncSession,
        object_class_dao: ObjectClassDAO,
    ) -> None:
        """Initialize Entity Type DAO with a database session."""
        self.__session = session
        self.__object_class_dao = object_class_dao

    async def _get_raw(self, _id: int) -> EntityType:
        """Get Entity Type by id."""
        entity_type = await self.__session.get(EntityType, _id)
        if not entity_type:
            raise EntityTypeNotFoundError(
                f"Entity Type with id {_id} not found.",
            )
        return entity_type

    async def get(self, _id: int) -> EntityTypeDTO:
        """Get Entity Type by id."""
        return _convert(await self._get_raw(_id))

    async def get_all(self) -> list[EntityTypeDTO]:
        """Get all Entity Types."""
        return [
            _convert(entity_type)
            for entity_type in await self.__session.scalars(
                select(EntityType),
            )
        ]

    async def create(self, dto: EntityTypeDTO) -> None:
        """Create a new Entity Type."""
        try:
            entity_type = EntityType(
                name=dto.name,
                object_class_names=sorted(set(dto.object_class_names)),
                is_system=dto.is_system,
            )
            self.__session.add(entity_type)
            await self.__session.flush()
        except IntegrityError:
            raise EntityTypeAlreadyExistsError(
                f"Entity Type with name '{dto.name}' already exists.",
            )

    async def update(self, _id: int, dto: EntityTypeDTO) -> None:
        """Update an Entity Type."""
        entity_type = await self._get_raw(_id)

        try:
            await self.__object_class_dao.is_all_object_classes_exists(
                dto.object_class_names,
            )

            entity_type.name = dto.name

            # Sort object_class_names to ensure a
            # consistent order for database operations
            # and to facilitate duplicate detection.

            entity_type.object_class_names = sorted(
                dto.object_class_names,
            )
            result = await self.__session.execute(
                select(Directory)
                .join(Directory.entity_type)
                .where(EntityType.name == entity_type.name)
                .options(selectinload(Directory.attributes)),
            )  # fmt: skip

            await self.__session.execute(
                delete(Attribute)
                .where(
                    Attribute.directory_id.in_(
                        select(Directory.id)
                        .join(Directory.entity_type)
                        .where(EntityType.name == entity_type.name),
                    ),
                    or_(
                        Attribute.name == "objectclass",
                        Attribute.name == "objectClass",
                    ),
                ),
            )  # fmt: skip

            for directory in result.scalars():
                for object_class_name in entity_type.object_class_names:
                    self.__session.add(
                        Attribute(
                            directory=directory,
                            value=object_class_name,
                            name="objectClass",
                        ),
                    )

            await self.__session.flush()
        except IntegrityError:
            # NOTE: Session has autoflush, so we can fall in select requests
            await self.__session.rollback()
            raise EntityTypeCantModifyError(
                f"Entity Type with name '{dto.name}' and object class "
                f"names {dto.object_class_names} already exists.",
            )

    async def delete(self, _id: int) -> None:
        """Delete an Entity Type."""
        entity_type = await self._get_raw(_id)
        await self.__session.delete(entity_type)
        await self.__session.flush()

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

    async def get_one_by_name(
        self,
        entity_type_name: str,
    ) -> EntityTypeDTO:
        """Get single Entity Type by name.

        :param str entity_type_name: Entity Type name.
        :raise EntityTypeNotFoundError: If Entity Type not found.
        :return EntityType: Instance of Entity Type.
        """
        entity_type = await self.__session.scalar(
            select(EntityType)
            .where(EntityType.name == entity_type_name),
        )  # fmt: skip

        if not entity_type:
            raise EntityTypeNotFoundError(
                f"Entity Type with name '{entity_type_name}' not found.",
            )

        return _convert(entity_type)

    async def get_entity_type_by_object_class_names(
        self,
        object_class_names: Iterable[str],
    ) -> EntityType | None:
        """Get single Entity Type by object class names.

        :param Iterable[str] object_class_names: object class names.
        :return EntityType | None: Instance of Entity Type or None.
        """
        list_object_class_names = [name.lower() for name in object_class_names]
        result = await self.__session.execute(
            select(EntityType)
            .where(
                func.array_lowercase(EntityType.object_class_names).op("@>")(
                    list_object_class_names,
                ),
                func.array_lowercase(EntityType.object_class_names).op("<@")(
                    list_object_class_names,
                ),
            ),
        )  # fmt: skip

        return result.scalars().first()

    async def validate_name(
        self,
        name: str,
    ) -> None:
        if name in PRIMARY_ENTITY_TYPE_NAMES:
            raise EntityTypeCantModifyError(
                f"Can't change entity type name {name}",
            )

    async def get_entity_type_attributes(
        self,
        entity_type_name: str,
    ) -> list[str]:
        """Get all attribute names for an Entity Type.

        :param str entity_type_name: Entity Type name.
        :return list[str]: List of attribute names.
        """
        entity_type = await self.get_one_by_name(entity_type_name)

        if not entity_type.object_class_names:
            return []

        object_classes_query = await self.__session.scalars(
            select(ObjectClass)
            .where(ObjectClass.name.in_(entity_type.object_class_names))
            .options(
                selectinload(ObjectClass.attribute_types_must),
                selectinload(ObjectClass.attribute_types_may),
            ),
        )
        object_classes = list(object_classes_query.all())

        attribute_names = set()
        for object_class in object_classes:
            for attr in object_class.attribute_types_must:
                attribute_names.add(attr.name)
            for attr in object_class.attribute_types_may:
                attribute_names.add(attr.name)

        return sorted(list(attribute_names))

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
                    .where(Directory.entity_type_id.isnot(None)),
                ),
            ),
        )  # fmt: skip
        await self.__session.flush()

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
            ),
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
            object_class_names,
        )

        entity_type = await self.get_entity_type_by_object_class_names(
            object_class_names,
        )
        if not entity_type:
            entity_type_name = EntityType.generate_entity_type_name(
                directory=directory,
            )
            try:
                await self.create(
                    EntityTypeDTO(
                        id=None,
                        name=entity_type_name,
                        object_class_names=list(object_class_names),
                        is_system=is_system_entity_type,
                    ),
                )
            except IntegrityError:
                # NOTE: This happens when Race Condition occurs.
                # If the Entity Type already exists, we can ignore the error.
                pass

            entity_type = await self.get_entity_type_by_object_class_names(
                object_class_names,
            )

        directory.entity_type = entity_type
