"""Object Class DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from adaptix import P
from adaptix.conversion import (
    allow_unlinked_optional,
    get_converter,
    link_function,
)
from entities_legacy import AttributeTypeLegacy, ObjectClassLegacy
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from entities import Directory, EntityType
from enums import EntityTypeNames, KindType
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO, ObjectClassDTO
from ldap_protocol.ldap_schema.exceptions import (
    ObjectClassAlreadyExistsError,
    ObjectClassNotFoundError,
)
from repo.pg.tables import queryable_attr as qa

_convert_model_to_dto = get_converter(
    ObjectClassLegacy,
    ObjectClassDTO[int, AttributeTypeDTO],
    recipe=[
        allow_unlinked_optional(P[ObjectClassDTO].id),
        allow_unlinked_optional(P[ObjectClassDTO].entity_type_names),
        allow_unlinked_optional(P[AttributeTypeDTO].object_class_names),
        link_function(
            lambda _: "",
            P[AttributeTypeDTO].ldap_display_name,
        ),
        link_function(lambda x: x.kind, P[ObjectClassDTO].kind),
    ],
)


@dataclass
class ObjectClassCreateDTO:
    """Object Class DTO."""

    oid: str
    name: str
    kind: KindType
    is_system: bool
    attribute_types_must: list[AttributeTypeLegacy]
    attribute_types_may: list[AttributeTypeLegacy]
    superior: ObjectClassLegacy | None = None


class ObjectClassDAOLegacy:
    """Object Class DAO."""

    __session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Object Class DAO with session."""
        self.__session = session

    async def get_all(self) -> list[ObjectClassDTO[int, AttributeTypeDTO]]:
        """Get all Object Classes."""
        obj_classes = await self.__session.scalars(
            select(ObjectClassLegacy)
            .options(
                selectinload(qa(ObjectClassLegacy.attribute_types_may)),
                selectinload(qa(ObjectClassLegacy.attribute_types_must)),
            ),
        )  # fmt: skip
        return list(map(_convert_model_to_dto, obj_classes.all()))

    async def create(
        self,
        dto: ObjectClassCreateDTO,
    ) -> None:
        """Create a new Object Class."""
        try:
            object_class = ObjectClassLegacy(
                oid=dto.oid,
                name=dto.name,
                superior=dto.superior,
                kind=dto.kind,
                is_system=dto.is_system,
                attribute_types_must=dto.attribute_types_must,
                attribute_types_may=dto.attribute_types_may,
            )
            self.__session.add(object_class)
            await self.__session.flush()
        except IntegrityError:
            raise ObjectClassAlreadyExistsError(
                f"Object Class with oid '{dto.oid}' and name"
                + f" '{dto.name}' already exists.",
            )

    async def get_raw_by_name(self, name: str) -> ObjectClassLegacy:
        """Get single Object Class by name."""
        object_class = await self.__session.scalar(
            select(ObjectClassLegacy)
            .filter_by(name=name)
            .options(selectinload(qa(ObjectClassLegacy.attribute_types_may)))
            .options(selectinload(qa(ObjectClassLegacy.attribute_types_must))),
        )  # fmt: skip

        if not object_class:
            raise ObjectClassNotFoundError(
                f"Object Class with name '{name}' not found.",
            )
        return object_class

    async def delete_all_dirs(self) -> None:
        objcls_subq = (
            select(qa(EntityType.id))
            .where(qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS)
            .scalar_subquery()
        )
        await self.__session.execute(
            delete(Directory)
            .where(qa(Directory.entity_type_id).in_(objcls_subq)),
        )  # fmt: skip

    async def get(self, name: str) -> ObjectClassDTO[int, AttributeTypeDTO]:
        """Get single Object Class by name."""
        return _convert_model_to_dto(await self.get_raw_by_name(name))
