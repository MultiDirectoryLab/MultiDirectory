"""Attribute Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable, Sequence

from adaptix import P
from adaptix.conversion import (
    allow_unlinked_optional,
    get_converter,
    link_function,
)
from entities_appendix import AttributeType, ObjectClass
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


class AttributeTypeDAODeprecated:
    """Attribute Type DAO."""

    __session: AsyncSession

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        """Initialize Attribute Type DAO with session."""
        self.__session = session

    async def delete_table_deprecated(self) -> None:
        await self.__session.execute(
            text('DROP TABLE IF EXISTS "AttributeTypes" CASCADE'),
        )

    async def get_deprecated(
        self,
        name: str,
    ) -> AttributeTypeDTO:
        return _convert_model_to_dto(await self._get_one_raw_by_name(name))

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

    async def update_deprecated(
        self,
        name: str,
        dto: AttributeTypeDTO,
    ) -> None:
        """Update Attribute Type.

        Docs:
            ANR (Ambiguous Name Resolution) inclusion can be modified for
            all attributes, including system ones, as it's a search
            optimization setting that doesn't affect the LDAP schema
            structure or data integrity.

            Other properties (`syntax`, `single_value`, `no_user_modification`)
            can only be modified for non-system attributes to preserve
            LDAP schema integrity.
        """
        obj = await self._get_one_raw_by_name(name)

        obj.is_included_anr = dto.is_included_anr

        if not obj.is_system:
            obj.syntax = dto.syntax
            obj.single_value = dto.single_value
            obj.no_user_modification = dto.no_user_modification

        await self.__session.flush()

    async def get_all_deprecated(self) -> list[AttributeTypeDTO]:
        """Get all Attribute Types."""
        return [
            _convert_model_to_dto(attribute_type)
            for attribute_type in await self.__session.scalars(
                select(AttributeType),
            )
        ]

    async def create_deprecated(self, dto: AttributeTypeDTO) -> None:
        """Create Attribute Type."""
        try:
            attribute_type = _convert_dto_to_model(dto)
            self.__session.add(attribute_type)
            await self.__session.flush()

        except IntegrityError:
            raise AttributeTypeAlreadyExistsError(
                f"Attribute Type with oid '{dto.oid}' and name"
                + f" '{dto.name}' already exists.",
            )

    async def zero_all_replicated_flags_deprecated(self) -> None:
        """Set replication flag to False for all Attribute Types."""
        await self.__session.execute(
            update(AttributeType)
            .values({"system_flags": 0}),
        )  # fmt: skip

    async def set_attrs_replication_flag_deprecated(
        self,
        names: tuple[str, ...],
        need_to_replicate: bool,
    ) -> None:
        """Set replication flag in systemFlags."""
        flag_value = 1 if need_to_replicate else 0
        await self.__session.execute(
            update(AttributeType)
            .where(qa(AttributeType.name).in_(names))
            .values({"system_flags": flag_value}),
        )

    async def false_all_is_included_anr_deprecated(self) -> None:
        """Set is_included_anr to False for all Attribute Types."""
        await self.__session.execute(
            update(AttributeType)
            .values({"is_included_anr": False}),
        )  # fmt: skip

    async def update_and_get_migration_f24ed_deprecated(
        self,
        names: Iterable[str],
    ) -> list[str]:
        """Update Attribute Types and return updated AttrType names."""
        result = await self.__session.scalars(
            update(AttributeType)
            .where(qa(AttributeType.name).in_(names))
            .values({"is_included_anr": True})
            .returning(qa(AttributeType.name)),
        )
        return list(result.all())

    async def update_sys_flags_deprecated(
        self,
        name: str,
        dto: AttributeTypeDTO,
    ) -> None:
        """Update system flags of Attribute Type."""
        obj = await self._get_one_raw_by_name(name)
        obj.system_flags = dto.system_flags
        await self.__session.flush()

    async def _get_one_raw_by_name(self, name: str) -> AttributeType:
        attribute_type = await self.__session.scalar(
            select(AttributeType)
            .filter_by(name=name),
        )  # fmt: skip

        if not attribute_type:
            raise AttributeTypeNotFoundError(
                f"Attribute Type with name '{name}' not found.",
            )
        return attribute_type

    async def get_all_raw_by_names_deprecated(
        self,
        names: list[str] | set[str],
    ) -> Sequence[AttributeType]:
        """Get list of Attribute Types by names."""
        res = await self.__session.scalars(
            select(AttributeType)
            .where(qa(AttributeType.name).in_(names)),
        )  # fmt: skip
        return res.all()

    async def get_all_by_names_deprecated(
        self,
        names: list[str] | set[str],
    ) -> list[AttributeTypeDTO[int]]:
        """Get list of Attribute Types by names.

        :param list[str] names: Attribute Type names.
        :return list[AttributeTypeDTO]: List of Attribute Types.
        """
        if not names:
            return []

        query = await self.__session.scalars(
            select(AttributeType)
            .where(qa(AttributeType.name).in_(names)),
        )  # fmt: skip
        return list(map(_convert_model_to_dto, query.all()))
