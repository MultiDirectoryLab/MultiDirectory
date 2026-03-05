"""Object Class DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable, Literal

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from entities import Attribute, Directory, EntityType
from enums import EntityTypeNames
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult
from repo.pg.tables import queryable_attr as qa

from ..dto import ObjectClassDTO
from ..exceptions import ObjectClassCantModifyError, ObjectClassNotFoundError


def _converter(dir_: Directory) -> ObjectClassDTO[int, str]:
    return ObjectClassDTO(
        oid=dir_.attributes_dict.get("oid")[0],  # type: ignore
        name=dir_.name,
        superior_name=dir_.attributes_dict.get("superior_name")[0],  # type: ignore
        kind=dir_.attributes_dict.get("kind")[0],  # type: ignore
        is_system=dir_.is_system,
        attribute_types_must=dir_.attributes_dict.get(
            "attribute_types_must",
            [],
        ),
        attribute_types_may=dir_.attributes_dict.get(
            "attribute_types_may",
            [],
        ),
        id=dir_.id,
        entity_type_names=set(),
    )


class ObjectClassDAO:
    """Object Class DAO."""

    __session: AsyncSession

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        """Initialize Object Class DAO with session."""
        self.__session = session

    async def get_all(self) -> list[ObjectClassDTO[int, str]]:
        """Get all Object Classes."""
        return [
            _converter(object_class)
            for object_class in await self.__session.scalars(
                select(Directory)
                .join(qa(Directory.entity_type))
                .filter(qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS)
                .options(selectinload(qa(Directory.attributes))),
            )
        ]

    async def get_object_class_names_include_attribute_type(
        self,
        attribute_type_name: str,
    ) -> set[str]:
        """Get all Object Class names include Attribute Type name."""
        result = await self.__session.scalars(
            select(qa(Directory.name))
            .select_from(qa(Directory))
            .join(qa(Directory.entity_type))
            .join(qa(Directory.attributes))
            .filter(
                qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
                qa(Attribute.name).in_(("attribute_types_must","attribute_types_may")),
                func.lower(qa(Attribute.value)) == attribute_type_name.lower(),
            ),
        )  # fmt: skip
        return set(result.all())

    async def delete(self, name: str) -> None:
        """Delete Object Class."""
        object_class = await self.get_dir(name)
        await self.__session.delete(object_class)
        await self.__session.flush()

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult[Directory, ObjectClassDTO]:
        """Retrieve paginated Object Classes.

        :param PaginationParams params: page_size and page_number.
        :return PaginationResult: Chunk of Object Classes and metadata.
        """
        filters = [
            qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
        ]

        query = (
            select(Directory)
            .join(qa(Directory.entity_type))
            .filter(*filters)
            .options(selectinload(qa(Directory.attributes)))
            .order_by(qa(Directory.id))
        )

        return await PaginationResult[Directory, ObjectClassDTO].get(
            params=params,
            query=query,
            converter=_converter,
            session=self.__session,
        )

    async def is_all_object_classes_exists(
        self,
        names: Iterable[str],
    ) -> Literal[True]:
        """Check if all Object Classes exist.

        :param list[str] names: Object Class names.
        :raise ObjectClassNotFoundError: If Object Class not found.
        :return bool.
        """
        names = set(object_class.lower() for object_class in names)

        count_query = (
            select(func.count())
            .select_from(Directory)
            .join(qa(Directory.entity_type))
            .filter(
                qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
                func.lower(qa(Directory.name)).in_(names),
            )
        )

        result = await self.__session.scalar(count_query)
        count_ = int(result or 0)

        if count_ != len(names):
            raise ObjectClassNotFoundError(
                f"Not all Object Classes\
                    with names {names} ( != {count_} ) found.",
            )

        return True

    async def get(self, name: str) -> ObjectClassDTO:
        dir_ = await self.get_dir(name)
        if not dir_:
            raise ObjectClassNotFoundError(
                f"Object Class with name '{name}' not found.",
            )

        return _converter(dir_)

    async def get_dir(self, name: str) -> Directory | None:
        res = await self.__session.scalars(
            select(Directory)
            .join(qa(Directory.entity_type))
            .filter(
                qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
                qa(Directory.name) == name,
            )
            .options(selectinload(qa(Directory.attributes))),
        )
        return res.first()

    async def get_all_by_names(
        self,
        names: list[str] | set[str],
    ) -> list[ObjectClassDTO]:
        """Get list of Object Classes by names.

        :param list[str] names: Object Classes names.
        :return list[ObjectClassDTO]: List of Object Classes.
        """
        query = await self.__session.scalars(
            select(Directory)
            .join(qa(Directory.entity_type))
            .filter(
                qa(Directory.name).in_(names),
                qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
            )
            .options(selectinload(qa(Directory.attributes))),
        )
        return list(map(_converter, query.all()))

    async def update(self, name: str, dto: ObjectClassDTO[None, str]) -> None:
        """Update Object Class."""
        obj = await self.get(name)
        if obj.is_system:
            raise ObjectClassCantModifyError(
                "System Object Class cannot be modified.",
            )

        await self.__session.execute(
            delete(Attribute).where(
                qa(Attribute.directory_id) == obj.id,
                qa(Attribute.name).in_(
                    ("attribute_types_must", "attribute_types_may"),
                ),
            ),
        )

        for name in dto.attribute_types_may:
            self.__session.add(
                Attribute(
                    directory_id=obj.id,
                    name="attribute_types_may",
                    value=name,
                ),
            )

        for name in dto.attribute_types_must:
            self.__session.add(
                Attribute(
                    directory_id=obj.id,
                    name="attribute_types_must",
                    value=name,
                ),
            )

        await self.__session.flush()

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete not system Object Classes by Names.

        :param list[str] names: Object Classes names.
        :return None.
        """
        subq = (
            select(func.unnest(qa(EntityType.object_class_names)))
            .where(qa(EntityType.object_class_names).isnot(None))
        )  # fmt: skip

        await self.__session.execute(
            delete(Directory)
            .where(
                qa(Directory.entity_type).has(qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS),  # noqa: E501
                qa(Directory.name).in_(names),
                qa(Directory.is_system).is_(False),
                ~qa(Directory.name).in_(subq),
            ),
        )  # fmt: skip
