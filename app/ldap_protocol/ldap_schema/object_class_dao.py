"""Object Class DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import asdict
from typing import Iterable, Literal

from adaptix.conversion import get_converter
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from abstract_dao import AbstractDAO
from enums import KindType
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.dto import ObjectClassDTO, ObjectClassUpdateDTO
from ldap_protocol.ldap_schema.exceptions import (
    ObjectClassAlreadyExistsError,
    ObjectClassCantModifyError,
    ObjectClassNotFoundError,
)
from ldap_protocol.utils.pagination import (
    PaginationParams,
    PaginationResult,
    build_paginated_search_query,
)
from models import AttributeType, EntityType, ObjectClass

_converter = get_converter(ObjectClass, ObjectClassDTO)


class ObjectClassDAO(AbstractDAO[ObjectClassDTO]):
    """Object Class DAO."""

    __session: AsyncSession
    __attribute_type_dao: AttributeTypeDAO

    def __init__(
        self,
        session: AsyncSession,
        attribute_type_dao: AttributeTypeDAO,
    ) -> None:
        """Initialize Object Class DAO with session."""
        self.__session = session
        self.__attribute_type_dao = attribute_type_dao

    async def _get_raw(self, _id: int) -> ObjectClass:
        """Get raw Object Class by id."""
        object_class = await self.__session.scalar(
            select(ObjectClass).where(ObjectClass.id == _id),
        )
        if not object_class:
            raise ObjectClassNotFoundError(
                f"Object Class with id {_id} not found.",
            )
        return object_class

    async def get(self, _id: int) -> ObjectClassDTO:
        """Get Object Class by id."""
        return _converter(await self._get_raw(_id))

    async def get_all(self) -> list[ObjectClassDTO]:
        """Get all Object Classes."""
        return [
            _converter(object_class)
            for object_class in await self.__session.scalars(
                select(ObjectClass),
            )
        ]

    async def create(self, dto: ObjectClassDTO) -> None:
        """Create Object Class."""
        dto_dict = asdict(dto)
        dto_dict.pop("attribute_types_must", None)
        dto_dict.pop("attribute_types_may", None)

        object_class = ObjectClass(**dto_dict)
        self.__session.add(object_class)
        await self.__session.flush()

    async def update(self, _id: int, dto: ObjectClassDTO) -> None:
        """Update Object Class."""
        object_class = await self._get_raw(_id)
        object_class.oid = dto.oid
        object_class.name = dto.name
        object_class.superior_name = dto.superior_name
        object_class.kind = dto.kind
        object_class.is_system = dto.is_system
        await self.__session.flush()

    async def delete(self, _id: int) -> None:
        """Delete Object Class."""
        object_class = await self._get_raw(_id)
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
            order_by_field=ObjectClass.id,
            params=params,
            search_field=ObjectClass.name,
        )

        return await PaginationResult[ObjectClass].get(
            params=params,
            query=query,
            session=self.__session,
        )

    async def create_one(
        self,
        oid: str,
        name: str,
        superior_name: str | None,
        kind: KindType,
        is_system: bool,
        attribute_type_names_must: list[str],
        attribute_type_names_may: list[str],
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
            if superior_name:
                superior_query = await self.__session.scalars(
                    select(ObjectClass).where(
                        ObjectClass.name == superior_name,
                    ),
                )
                superior = superior_query.first()
            if superior_name and not superior:
                raise ObjectClassNotFoundError(
                    f"Superior (parent) Object class {superior_name} not found\
                        in schema.",
                )

            attribute_types_may_filtered = [
                name
                for name in attribute_type_names_may
                if name not in attribute_type_names_must
            ]

            if attribute_type_names_must:
                must_query = await self.__session.scalars(
                    select(AttributeType).where(
                        AttributeType.name.in_(attribute_type_names_must),
                    ),
                )
                attribute_types_must = list(must_query.all())
            else:
                attribute_types_must = []

            if attribute_types_may_filtered:
                may_query = await self.__session.scalars(
                    select(AttributeType).where(
                        AttributeType.name.in_(attribute_types_may_filtered),
                    ),
                )
                attribute_types_may = list(may_query.all())
            else:
                attribute_types_may = []

            object_class = ObjectClass(
                oid=oid,
                name=name,
                superior=superior,
                kind=kind,
                is_system=is_system,
                attribute_types_must=attribute_types_must,
                attribute_types_may=attribute_types_may,
            )
            self.__session.add(object_class)
            await self.__session.flush()
        except IntegrityError:
            raise ObjectClassAlreadyExistsError(
                f"Object Class with oid '{oid}' and name"
                + f" '{name}' already exists.",
            )

    async def _count_exists_object_class_by_names(
        self,
        object_class_names: Iterable[str],
    ) -> int:
        """Count exists Object Class by names.

        :param list[str] object_class_names: Object Class names.
        :return int.
        """
        count_query = (
            select(func.count())
            .select_from(ObjectClass)
            .where(func.lower(ObjectClass.name).in_(object_class_names))
        )
        result = await self.__session.scalars(count_query)
        return result.one()

    async def is_all_object_classes_exists(
        self,
        object_class_names: Iterable[str],
    ) -> Literal[True]:
        """Check if all Object Classes exist.

        :param list[str] object_class_names: Object Class names.
        :raise ObjectClassNotFoundError: If Object Class not found.
        :return bool.
        """
        object_class_names = set(
            object_class.lower() for object_class in object_class_names
        )

        count_ = await self._count_exists_object_class_by_names(
            object_class_names,
        )

        if count_ != len(object_class_names):
            raise ObjectClassNotFoundError(
                f"Not all Object Classes\
                    with names {object_class_names} found.",
            )

        return True

    async def get_one_by_name(
        self,
        object_class_name: str,
    ) -> ObjectClassDTO:
        """Get single Object Class by name.

        :param str object_class_name: Object Class name.
        :raise ObjectClassNotFoundError: If Object Class not found.
        :return ObjectClass: Instance of Object Class.
        """
        object_class = await self.__session.scalar(
            select(ObjectClass)
            .where(ObjectClass.name == object_class_name)
            .options(
                selectinload(ObjectClass.attribute_types_must),
                selectinload(ObjectClass.attribute_types_may),
            ),
        )  # fmt: skip

        if not object_class:
            raise ObjectClassNotFoundError(
                f"Object Class with name '{object_class_name}' not found.",
            )

        return _converter(object_class)

    async def get_all_by_names(
        self,
        object_class_names: list[str] | set[str],
    ) -> list[ObjectClassDTO]:
        """Get list of Object Classes by names.

        :param list[str] object_class_names: Object Classes names.
        :return list[ObjectClassDTO]: List of Object Classes.
        """
        query = await self.__session.scalars(
            select(ObjectClass)
            .where(ObjectClass.name.in_(object_class_names))
            .options(
                selectinload(ObjectClass.attribute_types_must),
                selectinload(ObjectClass.attribute_types_may),
            ),
        )  # fmt: skip
        return list(map(_converter, query.all()))

    async def modify_one(
        self,
        object_class: ObjectClassDTO,
        new_statement: ObjectClassUpdateDTO,
    ) -> None:
        """Modify Object Class.

        :param ObjectClass object_class: Object Class.
        :param ObjectClassDTO new_statement: New statement ObjectClass
        :raise ObjectClassCantModifyError: If Object Class is system,\
            it cannot be changed.
        :return None.
        """
        if object_class.is_system:
            raise ObjectClassCantModifyError(
                "System Object Class cannot be modified.",
            )

        db_object_class = await self._get_raw(object_class.id)

        db_object_class.attribute_types_must.clear()
        db_object_class.attribute_types_may.clear()

        if new_statement.attribute_type_names_must:
            must_query = await self.__session.scalars(
                select(AttributeType).where(
                    AttributeType.name.in_(
                        new_statement.attribute_type_names_must,
                    ),
                ),
            )
            db_object_class.attribute_types_must.extend(must_query.all())

        attribute_types_may_filtered = [
            name
            for name in new_statement.attribute_type_names_may
            if name not in new_statement.attribute_type_names_must
        ]

        if attribute_types_may_filtered:
            may_query = await self.__session.scalars(
                select(AttributeType).where(
                    AttributeType.name.in_(attribute_types_may_filtered),
                ),
            )
            db_object_class.attribute_types_may.extend(list(may_query.all()))

        await self.__session.flush()

    async def delete_all_by_names(
        self,
        object_classes_names: list[str],
    ) -> None:
        """Delete not system Object Classes by Names.

        :param list[str] object_classes_names: Object Classes names.
        :return None.
        """
        await self.__session.execute(
            delete(ObjectClass)
            .where(
                ObjectClass.name.in_(object_classes_names),
                ObjectClass.is_system.is_(False),
                ~ObjectClass.name.in_(
                    select(func.unnest(EntityType.object_class_names))
                    .where(EntityType.object_class_names.isnot(None)),
                ),
            ),
        )  # fmt: skip
