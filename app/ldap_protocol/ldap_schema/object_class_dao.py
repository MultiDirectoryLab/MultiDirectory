"""Object Class DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable, Literal

from adaptix import P
from adaptix.conversion import (
    allow_unlinked_optional,
    get_converter,
    link_function,
)
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from abstract_dao import AbstractDAO
from entities import AttributeType, EntityType, ObjectClass
from ldap_protocol.utils.pagination import (
    PaginationParams,
    PaginationResult,
    build_paginated_search_query,
)
from repo.pg.tables import queryable_attr as qa

from .dto import AttributeTypeDTO, ObjectClassDTO
from .exceptions import (
    ObjectClassAlreadyExistsError,
    ObjectClassCantModifyError,
    ObjectClassNotFoundError,
)

_converter = get_converter(
    ObjectClass,
    ObjectClassDTO[int, AttributeTypeDTO],
    recipe=[
        allow_unlinked_optional(P[ObjectClassDTO].id),
        link_function(lambda x: x.kind, P[ObjectClassDTO].kind),
    ],
)


class ObjectClassDAO(AbstractDAO[ObjectClassDTO, str]):
    """Object Class DAO."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Object Class DAO with session."""
        self.__session = session

    async def get_all(self) -> list[ObjectClassDTO[int, AttributeTypeDTO]]:
        """Get all Object Classes."""
        return [
            _converter(object_class)
            for object_class in await self.__session.scalars(
                select(ObjectClass),
            )
        ]

    async def get_object_class_names_include_attribute_type(
        self,
        attribute_type_name: str,
    ) -> set[str]:
        """Get all Object Class names include Attribute Type name."""
        result = await self.__session.execute(
            select(qa(ObjectClass.name))
            .where(
                or_(
                    qa(ObjectClass.attribute_types_must).any(name=attribute_type_name),
                    qa(ObjectClass.attribute_types_may).any(name=attribute_type_name),
                ),
            ),
        )  # fmt: skip
        return set(row[0] for row in result.fetchall())

    async def delete(self, _id: str) -> None:
        """Delete Object Class."""
        object_class = await self._get_one_raw_by_name(_id)
        await self.__session.delete(object_class)
        await self.__session.flush()

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated Object Classes.

        :param PaginationParams params: page_size and page_number.
        :return PaginationResult: Chunk of Object Classes and metadata.
        """
        query = build_paginated_search_query(
            model=ObjectClass,
            order_by_field=qa(ObjectClass.id),
            params=params,
            search_field=qa(ObjectClass.name),
            load_params=(
                selectinload(qa(ObjectClass).attribute_types_may),
                selectinload(qa(ObjectClass).attribute_types_must),
            ),
        )

        return await PaginationResult[ObjectClass].get(
            params=params,
            query=query,
            session=self.__session,
        )

    async def create(
        self,
        dto: ObjectClassDTO[None, str],
    ) -> None:
        """Create a new Object Class.

        :param str oid: OID.
        :param str name: Name.
        :param str | None superior_name: Parent Object Class.
        :param KindType kind: Kind.
        :param bool is_system: Object Class is system.
        :param list[str] attribute_type_names_must: Attribute Types must.
        :param list[str] attribute_type_names_may: Attribute Types may.
        :raise ObjectClassNotFoundError: If superior Object Class not found.
        :return None.
        """
        try:
            superior = None
            if dto.superior_name:
                superior = await self.__session.scalar(
                    select(ObjectClass)
                    .filter_by(name=dto.superior_name),
                )  # fmt: skip

            if dto.superior_name and not superior:
                raise ObjectClassNotFoundError(
                    f"Superior (parent) Object class {dto.superior_name} "
                    "not found in schema.",
                )

            attribute_types_may_filtered = [
                name
                for name in dto.attribute_types_may
                if name not in dto.attribute_types_must
            ]

            if dto.attribute_types_must:
                res = await self.__session.scalars(
                    select(AttributeType)
                    .where(qa(AttributeType.name).in_(dto.attribute_types_must)),
                )  # fmt: skip
                attribute_types_must = list(res.all())

            else:
                attribute_types_must = []

            if attribute_types_may_filtered:
                res = await self.__session.scalars(
                    select(AttributeType)
                    .where(
                        qa(AttributeType.name).in_(attribute_types_may_filtered),
                    ),
                )  # fmt: skip
                attribute_types_may = list(res.all())
            else:
                attribute_types_may = []

            object_class = ObjectClass(
                oid=dto.oid,
                name=dto.name,
                superior=superior,
                kind=dto.kind,
                is_system=dto.is_system,
                attribute_types_must=attribute_types_must,
                attribute_types_may=attribute_types_may,
            )
            self.__session.add(object_class)
            await self.__session.flush()
        except IntegrityError:
            raise ObjectClassAlreadyExistsError(
                f"Object Class with oid '{dto.oid}' and name"
                + f" '{dto.name}' already exists.",
            )

    async def _count_exists_object_class_by_names(
        self,
        names: Iterable[str],
    ) -> int:
        """Count exists Object Class by names.

        :param list[str] names: Object Class names.
        :return int.
        """
        count_query = (
            select(func.count())
            .select_from(ObjectClass)
            .where(func.lower(ObjectClass.name).in_(names))
        )
        result = await self.__session.scalars(count_query)
        return result.one()

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

        count_ = await self._count_exists_object_class_by_names(
            names,
        )

        if count_ != len(names):
            raise ObjectClassNotFoundError(
                f"Not all Object Classes\
                    with names {names} found.",
            )

        return True

    async def _get_one_raw_by_name(self, name: str) -> ObjectClass:
        """Get single Object Class by name.

        :param str name: Object Class name.
        :raise ObjectClassNotFoundError: If Object Class not found.
        :return ObjectClass: Instance of Object Class.
        """
        object_class = await self.__session.scalar(
            select(ObjectClass)
            .filter_by(name=name)
            .options(selectinload(qa(ObjectClass.attribute_types_may)))
            .options(selectinload(qa(ObjectClass.attribute_types_must))),
        )  # fmt: skip

        if not object_class:
            raise ObjectClassNotFoundError(
                f"Object Class with name '{name}' not found.",
            )
        return object_class

    async def get(self, _id: str) -> ObjectClassDTO:
        """Get single Object Class by id.

        :param str _id: Object Class name.
        :raise ObjectClassNotFoundError: If Object Class not found.
        :return ObjectClass: Instance of Object Class.
        """
        return _converter(await self._get_one_raw_by_name(_id))

    async def get_all_by_names(
        self,
        names: list[str] | set[str],
    ) -> list[ObjectClassDTO]:
        """Get list of Object Classes by names.

        :param list[str] names: Object Classes names.
        :return list[ObjectClassDTO]: List of Object Classes.
        """
        query = await self.__session.scalars(
            select(ObjectClass)
            .where(qa(ObjectClass.name).in_(names))
            .options(
                selectinload(qa(ObjectClass.attribute_types_must)),
                selectinload(qa(ObjectClass.attribute_types_may)),
            ),
        )  # fmt: skip
        return list(map(_converter, query.all()))

    async def update(self, _id: str, dto: ObjectClassDTO[None, str]) -> None:
        """Modify Object Class.

        :param ObjectClassDTO object_class: Object Class.
        :param ObjectClassDTO dto: New statement ObjectClass
        :raise ObjectClassCantModifyError: If Object Class is system,\
            it cannot be changed.
        :return None.
        """
        obj = await self._get_one_raw_by_name(_id)
        if obj.is_system:
            raise ObjectClassCantModifyError(
                "System Object Class cannot be modified.",
            )

        obj.attribute_types_must.clear()
        obj.attribute_types_may.clear()

        if dto.attribute_types_must:
            must_query = await self.__session.scalars(
                select(AttributeType).where(
                    qa(AttributeType.name).in_(
                        dto.attribute_types_must,
                    ),
                ),
            )
            obj.attribute_types_must.extend(must_query.all())

        attribute_types_may_filtered = [
            name
            for name in dto.attribute_types_may
            if name not in dto.attribute_types_must
        ]

        if attribute_types_may_filtered:
            may_query = await self.__session.scalars(
                select(AttributeType)
                .where(qa(AttributeType.name).in_(attribute_types_may_filtered)),
            )  # fmt: skip
            obj.attribute_types_may.extend(list(may_query.all()))

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
            delete(ObjectClass)
            .where(
                qa(ObjectClass.name).in_(names),
                qa(ObjectClass.is_system).is_(False),
                ~qa(ObjectClass.name).in_(subq),
            ),
        )  # fmt: skip
