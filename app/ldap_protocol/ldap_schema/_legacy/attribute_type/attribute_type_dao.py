"""Attribute Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import P
from adaptix.conversion import (
    allow_unlinked_optional,
    get_converter,
    link_function,
)
from entities_legacy import AttributeTypeLegacy, ObjectClassLegacy
from sqlalchemy import delete, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Directory, EntityType
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
    AttributeTypeNotFoundError,
)
from repo.pg.tables import queryable_attr as qa

_convert_model_to_dto = get_converter(
    AttributeTypeLegacy,
    AttributeTypeDTO,
    recipe=[
        allow_unlinked_optional(P[AttributeTypeDTO].object_class_names),
    ],
)
_convert_dto_to_model = get_converter(
    AttributeTypeDTO,
    AttributeTypeLegacy,
    recipe=[
        link_function(
            lambda _: None,
            P[AttributeTypeLegacy].id,
        ),
    ],
)


class AttributeTypeDAOLegacy:
    """Attribute Type DAO."""

    __session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Attribute Type DAO with session."""
        self.__session = session

    async def delete_all_dirs(self) -> None:
        attr_subq = (
            select(qa(EntityType.id))
            .where(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE)
            .scalar_subquery(),
        )
        await self.__session.execute(
            delete(Directory)
            .where(qa(Directory.entity_type_id).in_(attr_subq)),
        )  # fmt: skip

    async def delete_table(self) -> None:
        await self.__session.execute(
            text('DROP TABLE IF EXISTS "AttributeTypes" CASCADE'),
        )

    async def get_object_class_names_include_attribute_type(
        self,
        attribute_type_name: str,
    ) -> set[str]:
        """Get all Object Class names include Attribute Type name."""
        result = await self.__session.execute(
            select(qa(ObjectClassLegacy.name))
            .where(
                or_(
                    qa(ObjectClassLegacy.attribute_types_must).any(name=attribute_type_name),
                    qa(ObjectClassLegacy.attribute_types_may).any(name=attribute_type_name),
                ),
            ),
        )  # fmt: skip
        return set(row[0] for row in result.fetchall())

    async def get_all(self) -> list[AttributeTypeDTO[int]]:
        """Get all Attribute Types."""
        res = await self.__session.scalars(select(AttributeTypeLegacy))
        return list(map(_convert_model_to_dto, res.all()))

    async def create(self, dto: AttributeTypeDTO[None]) -> None:
        """Create Attribute Type."""
        try:
            self.__session.add(_convert_dto_to_model(dto))
            await self.__session.flush()

        except IntegrityError:
            raise AttributeTypeAlreadyExistsError(
                f"Attribute Type with oid '{dto.oid}' and name"
                + f" '{dto.name}' already exists.",
            )

    async def zero_all_replicated_flags(self) -> None:
        """Set replication flag to False for all Attribute Types."""
        await self.__session.execute(update(AttributeTypeLegacy).values({"system_flags": 0}))  # fmt: skip # noqa: E501

    async def set_false_replication_flag(self, names: tuple[str, ...]) -> None:
        """Set replication flag in systemFlags."""
        await self.__session.execute(
            update(AttributeTypeLegacy)
            .where(qa(AttributeTypeLegacy.name).in_(names))
            .values({"system_flags": 0}),
        )

    async def false_all_is_included_anr(self) -> None:
        """Set is_included_anr to False for all Attribute Types."""
        await self.__session.execute(update(AttributeTypeLegacy).values({"is_included_anr": False}))  # fmt: skip # noqa: E501

    async def mark_anr_included_by_attr_names(
        self,
        names: tuple[str, ...],
    ) -> list[str]:
        """Update Attribute Types and return updated AttrType names."""
        result = await self.__session.scalars(
            update(AttributeTypeLegacy)
            .where(qa(AttributeTypeLegacy.name).in_(names))
            .values({"is_included_anr": True})
            .returning(qa(AttributeTypeLegacy.name)),
        )
        return list(result.all())

    async def get(self, name: str) -> AttributeTypeDTO[int]:
        attribute_type = await self.__session.scalar(
            select(AttributeTypeLegacy)
            .filter_by(name=name),
        )  # fmt: skip

        if not attribute_type:
            raise AttributeTypeNotFoundError(
                f"Attribute Type with name '{name}' not found.",
            )
        return _convert_model_to_dto(attribute_type)

    async def get_all_raw_by_names(
        self,
        names: list[str],
    ) -> list[AttributeTypeLegacy]:
        """Get list of Attribute Types by names."""
        res = await self.__session.scalars(
            select(AttributeTypeLegacy)
            .where(qa(AttributeTypeLegacy.name).in_(names)),
        )  # fmt: skip
        return list(res.all())
