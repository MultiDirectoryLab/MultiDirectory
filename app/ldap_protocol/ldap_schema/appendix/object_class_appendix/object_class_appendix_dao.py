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
from entities_appendix import AttributeType, ObjectClass
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_schema.dto import AttributeTypeDTO, ObjectClassDTO
from ldap_protocol.ldap_schema.exceptions import (
    ObjectClassAlreadyExistsError,
    ObjectClassNotFoundError,
)
from repo.pg.tables import queryable_attr as qa

_converter = get_converter(
    ObjectClass,
    ObjectClassDTO[int, AttributeTypeDTO],
    recipe=[
        allow_unlinked_optional(P[ObjectClassDTO].id),
        allow_unlinked_optional(P[ObjectClassDTO].entity_type_names),
        allow_unlinked_optional(P[AttributeTypeDTO].object_class_names),
        link_function(lambda x: x.kind, P[ObjectClassDTO].kind),
    ],
)


class ObjectClassDAODeprecated:
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

    async def create(
        self,
        dto: ObjectClassDTO[None, str],
    ) -> None:
        """Create a new Object Class."""
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
                    .where(qa(AttributeType.name).in_(attribute_types_may_filtered)),
                )  # fmt: skip
                attribute_types_may = list(res.all())
            else:
                attribute_types_may = []

            # TODO uncomment
            # if len(attribute_types_may_filtered) != len(
            #     attribute_types_may,
            # ) or len(dto.attribute_types_must) != len(attribute_types_must):
            #     raise ObjectClassNotFoundError(
            #         "Not all Attribute Types specified in Object Class "
            #         "definition found in schema.",
            #     )

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
            .select_from(ObjectClass)
            .where(func.lower(ObjectClass.name).in_(names))
        )
        result = await self.__session.scalars(count_query)
        count_ = result.one()

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

    async def get_raw_by_name(self, name: str) -> ObjectClass:
        """Get Object Class by name without related data."""
        return await self._get_one_raw_by_name(name)

    async def get(self, name: str) -> ObjectClassDTO[int, AttributeTypeDTO]:
        """Get single Object Class by name.

        :param str name: Object Class name.
        :raise ObjectClassNotFoundError: If Object Class not found.
        :return ObjectClass: Instance of Object Class.
        """
        return _converter(await self._get_one_raw_by_name(name))
