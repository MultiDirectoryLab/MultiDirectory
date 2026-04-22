"""Attribute Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from entities import Directory, EntityType
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.attribute_type.constants import AttributeTypeAttributeNames as Names
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO
from ldap_protocol.ldap_schema.exceptions import AttributeTypeNotFoundError
from ldap_protocol.utils.pagination import PaginationParams, PaginationResult
from repo.pg.tables import queryable_attr as qa


def _convert_model_to_dto(directory: Directory) -> AttributeTypeDTO[int]:
    return AttributeTypeDTO[int](
        id=directory.id,
        name=directory.name,
        ldap_display_name=directory.attributes_dict[Names.LDAP_DISPLAY_NAME][0],
        oid=directory.attributes_dict[Names.OID][0],
        syntax=directory.attributes_dict[Names.SYNTAX][0],
        single_value=directory.attributes_dict[Names.SINGLE_VALUE][0] == "True",
        no_user_modification=directory.attributes_dict[Names.NO_USER_MODIFICATION][0] == "True",
        is_system=directory.is_system,
        system_flags=int(directory.attributes_dict[Names.SYSTEM_FLAGS][0]),
        is_included_anr=directory.attributes_dict[Names.IS_INCLUDED_ANR][0] == "True",
        object_class_names=set(),
    )


class AttributeTypeDAO:
    """Attribute Type DAO."""

    __session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Attribute Type DAO with session."""
        self.__session = session

    async def _get_dir(self, name: str) -> Directory | None:
        res = await self.__session.scalars(
            select(Directory)
            .join(qa(Directory.entity_type))
            .options(selectinload(qa(Directory.attributes)))
            .where(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE, qa(Directory.name) == name)
        )
        dir_ = res.first()
        return dir_

    async def get_all_names_by_names(self, names: list[str]) -> list[str]:
        res = await self.__session.scalars(
            select(qa(Directory.name))
            .join(qa(Directory.entity_type))
            .where(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE, qa(Directory.name).in_(names))
        )
        return list(res.all())

    async def get_all(self) -> list[AttributeTypeDTO]:
        res = await self.__session.scalars(
            select(Directory)
            .join(qa(Directory.entity_type))
            .options(selectinload(qa(Directory.attributes)))
            .where(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE)
        )
        return list(map(_convert_model_to_dto, res.all()))

    async def get(self, name: str) -> AttributeTypeDTO:
        """Get Attribute Type by name."""
        dir_ = await self._get_dir(name)
        if not dir_:
            raise AttributeTypeNotFoundError(f"Attribute Type with name '{name}' not found.")

        return _convert_model_to_dto(dir_)

    async def update(self, name: str, dto: AttributeTypeDTO) -> None:
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
        dir_ = await self._get_dir(name)
        if not dir_:
            raise AttributeTypeNotFoundError(f"Attribute Type with name '{name}' not found.")

        for attr in dir_.attributes:
            if not dir_.is_system:
                if attr.name == Names.SYNTAX:
                    attr.value = dto.syntax
                elif attr.name == Names.SINGLE_VALUE:
                    attr.value = str(dto.single_value)
                elif attr.name == Names.NO_USER_MODIFICATION:
                    attr.value = str(dto.no_user_modification)
            else:
                if attr.name == Names.IS_INCLUDED_ANR:
                    attr.value = str(dto.is_included_anr)
                    break

        await self.__session.flush()

    async def update_sys_flags(self, name: str, dto: AttributeTypeDTO) -> None:
        """Update system flags of Attribute Type."""
        dir_ = await self._get_dir(name)
        if not dir_:
            raise AttributeTypeNotFoundError(f"Attribute Type with name '{name}' not found.")

        for attr in dir_.attributes:
            if attr.name == Names.SYSTEM_FLAGS:
                attr.value = str(dto.system_flags)
                break

        await self.__session.flush()

    async def get_paginator(self, params: PaginationParams) -> PaginationResult[Directory, AttributeTypeDTO]:
        """Retrieve paginated Attribute Types."""
        filters = [qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE]

        if params.query:
            filters.append(qa(Directory.name).ilike(f"%{params.query}%"))

        query = (
            select(Directory)
            .join(qa(Directory.entity_type))
            .where(*filters)
            .options(selectinload(qa(Directory.attributes)))
            .order_by(qa(Directory.id))
        )

        return await PaginationResult[Directory, AttributeTypeDTO].get(
            params=params, query=query, converter=_convert_model_to_dto, session=self.__session
        )

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete not system Attribute Types by names."""
        if not names:
            return

        await self.__session.execute(
            delete(Directory)
            .where(
                qa(Directory.entity_type).has(qa(EntityType.name) == EntityTypeNames.ATTRIBUTE_TYPE),
                qa(Directory.name).in_(names),
                qa(Directory.is_system).is_(False),
            ),
        )  # fmt: skip
        await self.__session.flush()
