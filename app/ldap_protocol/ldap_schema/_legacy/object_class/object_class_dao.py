"""Object Class DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import P
from adaptix.conversion import (
    allow_unlinked_optional,
    get_converter,
    link_function,
)
from entities_legacy import AttributeType, ObjectClass
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_schema.dto import AttributeTypeDTO, ObjectClassDTO
from ldap_protocol.ldap_schema.exceptions import (
    ObjectClassAlreadyExistsError,
    ObjectClassNotFoundError,
)
from repo.pg.tables import queryable_attr as qa

_convert_model_to_dto = get_converter(
    ObjectClass,
    ObjectClassDTO[int, AttributeTypeDTO],
    recipe=[
        allow_unlinked_optional(P[ObjectClassDTO].id),
        allow_unlinked_optional(P[ObjectClassDTO].entity_type_names),
        allow_unlinked_optional(P[AttributeTypeDTO].object_class_names),
        link_function(lambda x: x.kind, P[ObjectClassDTO].kind),
    ],
)


class ObjectClassDAOLegacy:
    """Object Class DAO."""

    __session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Object Class DAO with session."""
        self.__session = session

    async def get_all(self) -> list[ObjectClassDTO[int, AttributeTypeDTO]]:
        """Get all Object Classes."""
        obj_classes = await self.__session.scalars(
            select(ObjectClass)
            .options(
                selectinload(qa(ObjectClass.attribute_types_may)),
                selectinload(qa(ObjectClass.attribute_types_must)),
            ),
        )  # fmt: skip
        return list(map(_convert_model_to_dto, obj_classes.all()))

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

    async def get_raw_by_name(self, name: str) -> ObjectClass:
        """Get single Object Class by name."""
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

    async def delete_table(self) -> None:
        await self.__session.execute(
            text('DROP TABLE IF EXISTS "ObjectClasses" CASCADE'),
        )

    async def get(self, name: str) -> ObjectClassDTO[int, AttributeTypeDTO]:
        """Get single Object Class by name."""
        return _convert_model_to_dto(await self.get_raw_by_name(name))
