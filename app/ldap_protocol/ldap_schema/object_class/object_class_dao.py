"""Object Class DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable, Literal

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from entities import Attribute, Directory, EntityType
from enums import EntityTypeNames, KindType
from ldap_protocol.ldap_schema.object_class.constants import (
    ObjectClassAttributeNames as Names,
)
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult
from repo.pg.tables import queryable_attr as qa

from ..dto import ObjectClassDTO
from ..exceptions import (
    ObjectClassCantModifyError,
    ObjectClassNotFoundError,
    ObjectClassNotSetKindError,
)


def _convert_model_to_dto(dir_: Directory) -> ObjectClassDTO[int, str]:
    _oids = dir_.attributes_dict.get(Names.OID)
    oid = _oids[0] if _oids else ""

    _superior_names = dir_.attributes_dict.get(Names.SUPERIOR_NAME)
    superior_name = _superior_names[0] if _superior_names else ""

    _kinds = dir_.attributes_dict.get(Names.KIND)
    if not _kinds:
        raise ObjectClassNotSetKindError(
            f"Object Class '{dir_.name}' has no kind.",
        )
    kind = KindType(_kinds[0])

    attribute_types_must = dir_.attributes_dict.get(
        Names.ATTRIBUTE_TYPES_MUST,
        [],
    )
    attribute_types_may = dir_.attributes_dict.get(
        Names.ATTRIBUTE_TYPES_MAY,
        [],
    )

    return ObjectClassDTO(
        oid=oid,
        name=dir_.name,
        superior_name=superior_name,
        kind=kind,
        is_system=dir_.is_system,
        attribute_types_must=attribute_types_must,
        attribute_types_may=attribute_types_may,
        id=dir_.id,
        entity_type_names=set(),
    )  # fmt: skip


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
        result = await self.__session.scalars(
            select(Directory)
            .join(qa(Directory.entity_type))
            .where(qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS)
            .options(selectinload(qa(Directory.attributes))),
        )
        return list(map(_convert_model_to_dto, result))

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
            .where(
                qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
                qa(Attribute.name).in_(
                    (Names.ATTRIBUTE_TYPES_MUST, Names.ATTRIBUTE_TYPES_MAY),
                ),
                func.lower(qa(Attribute.value)) == attribute_type_name.lower(),
            ),
        )  # fmt: skip
        return set(result.all())

    async def delete(self, name: str) -> None:
        """Delete Object Class."""
        object_class = await self._get_dir(name)
        await self.__session.delete(object_class)
        await self.__session.flush()

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult[Directory, ObjectClassDTO]:
        """Retrieve paginated Object Classes."""
        filters = [qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS]

        if params.query:
            filters.append(qa(Directory.name).ilike(f"%{params.query}%"))

        query = (
            select(Directory)
            .join(qa(Directory.entity_type))
            .where(*filters)
            .options(selectinload(qa(Directory.attributes)))
            .order_by(qa(Directory.id))
        )

        return await PaginationResult[Directory, ObjectClassDTO].get(
            params=params,
            query=query,
            converter=_convert_model_to_dto,
            session=self.__session,
        )

    async def is_all_object_classes_exists(
        self,
        names: Iterable[str],
    ) -> Literal[True]:
        """Check if all Object Classes exist."""
        names = set(object_class.lower() for object_class in names)

        count_query = (
            select(func.count())
            .select_from(Directory)
            .join(qa(Directory.entity_type))
            .where(
                qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
                func.lower(qa(Directory.name)).in_(names),
            )
        )

        result = await self.__session.scalar(count_query)
        count_ = int(result or 0)

        if count_ != len(names):
            raise ObjectClassNotFoundError(
                f"Not all Object Classes with names {names} ( != {count_} ) found.",  # noqa: E501
            )

        return True

    async def get(self, name: str) -> ObjectClassDTO:
        dir_ = await self._get_dir(name)
        if not dir_:
            raise ObjectClassNotFoundError(
                f"Object Class with name '{name}' not found.",
            )

        return _convert_model_to_dto(dir_)

    async def _get_dir(self, name: str) -> Directory | None:
        res = await self.__session.scalars(
            select(Directory)
            .join(qa(Directory.entity_type))
            .where(
                qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
                qa(Directory.name) == name,
            )
            .options(selectinload(qa(Directory.attributes))),
        )
        return res.first()

    async def get_all_by_names(
        self,
        names: list[str] | set[str],
    ) -> list[ObjectClassDTO[int, str]]:
        """Get list of Object Classes by names."""
        query = await self.__session.scalars(
            select(Directory)
            .join(qa(Directory.entity_type))
            .where(
                qa(Directory.name).in_(names),
                qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
            )
            .options(selectinload(qa(Directory.attributes))),
        )
        return list(map(_convert_model_to_dto, query.all()))

    async def update(self, name: str, dto: ObjectClassDTO[None, str]) -> None:
        """Update Object Class."""
        obj = await self.get(name)
        if obj.is_system:
            raise ObjectClassCantModifyError(
                "System Object Class cannot be modified.",
            )

        await self.__session.execute(
            delete(Attribute)
            .where(
                qa(Attribute.directory_id) == obj.id,
                qa(Attribute.name).in_((Names.ATTRIBUTE_TYPES_MUST, Names.ATTRIBUTE_TYPES_MAY)),  # noqa: E501
            ),
        )  # fmt: skip

        for value in dto.attribute_types_may:
            self.__session.add(
                Attribute(
                    directory_id=obj.id,
                    name=Names.ATTRIBUTE_TYPES_MAY,
                    value=value,
                ),
            )

        for value in dto.attribute_types_must:
            self.__session.add(
                Attribute(
                    directory_id=obj.id,
                    name=Names.ATTRIBUTE_TYPES_MUST,
                    value=value,
                ),
            )

        await self.__session.flush()

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete not system Object Classes by Names."""
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
