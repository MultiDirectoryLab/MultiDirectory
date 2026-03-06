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
from entities_legacy import AttributeType, ObjectClass
from sqlalchemy import or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_schema.dto import AttributeTypeDTO
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
    AttributeTypeNotFoundError,
)
from repo.pg.tables import queryable_attr as qa

_convert_model_to_dto = get_converter(
    AttributeType,
    AttributeTypeDTO,
    recipe=[
        allow_unlinked_optional(P[AttributeTypeDTO].object_class_names),
    ],
)
_convert_dto_to_model = get_converter(
    AttributeTypeDTO,
    AttributeType,
    recipe=[
        link_function(
            lambda _: None,
            P[AttributeType].id,
        ),
    ],
)


class AttributeTypeDAOLegacy:
    """Attribute Type DAO."""

    __session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Attribute Type DAO with session."""
        self.__session = session

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
            select(qa(ObjectClass.name))
            .where(
                or_(
                    qa(ObjectClass.attribute_types_must).any(name=attribute_type_name),
                    qa(ObjectClass.attribute_types_may).any(name=attribute_type_name),
                ),
            ),
        )  # fmt: skip
        return set(row[0] for row in result.fetchall())

    async def get_all(self) -> list[AttributeTypeDTO[int]]:
        """Get all Attribute Types."""
        res = await self.__session.scalars(select(AttributeType))
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
        await self.__session.execute(update(AttributeType).values({"system_flags": 0}))  # fmt: skip # noqa: E501

    async def set_attrs_replication_flag(
        self,
        names: tuple[str, ...],
        need_to_replicate: bool,
    ) -> None:
        """Set replication flag in systemFlags."""
        await self.__session.execute(
            update(AttributeType)
            .where(qa(AttributeType.name).in_(names))
            .values({"system_flags": int(need_to_replicate)}),
        )

    async def false_all_is_included_anr(self) -> None:
        """Set is_included_anr to False for all Attribute Types."""
        await self.__session.execute(update(AttributeType).values({"is_included_anr": False}))  # fmt: skip # noqa: E501

    async def mark_anr_included_by_attr_names(
        self,
        names: tuple[str, ...],
    ) -> list[str]:
        """Update Attribute Types and return updated AttrType names."""
        result = await self.__session.scalars(
            update(AttributeType)
            .where(qa(AttributeType.name).in_(names))
            .values({"is_included_anr": True})
            .returning(qa(AttributeType.name)),
        )
        return list(result.all())

    async def get(self, name: str) -> AttributeTypeDTO[int]:
        attribute_type = await self.__session.scalar(
            select(AttributeType)
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
    ) -> list[AttributeType]:
        """Get list of Attribute Types by names."""
        res = await self.__session.scalars(
            select(AttributeType)
            .where(qa(AttributeType.name).in_(names)),
        )  # fmt: skip
        return list(res.all())
