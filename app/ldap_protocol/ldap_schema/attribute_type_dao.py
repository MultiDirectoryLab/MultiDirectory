"""Attribute Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix.conversion import get_converter
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_dao import AbstractDAO
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
    AttributeTypeCantModifyError,
    AttributeTypeNotFoundError,
)
from ldap_protocol.utils.pagination import (
    PaginationParams,
    PaginationResult,
    build_paginated_search_query,
)
from models import AttributeType

_convert = get_converter(AttributeType, AttributeTypeDTO)


class AttributeTypeDAO(AbstractDAO[AttributeTypeDTO]):
    """Attribute Type DAO."""

    __session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Attribute Type DAO with session."""
        self.__session = session

    async def _get_raw(self, _id: int) -> AttributeType:
        """Get Attribute Type by id."""
        attribute_type = await self.__session.get(AttributeType, _id)
        if not attribute_type:
            raise AttributeTypeNotFoundError(
                f"Attribute Type with id {_id} not found.",
            )
        return attribute_type

    async def get(self, _id: int) -> AttributeTypeDTO:
        """Get Attribute Type by id."""
        return _convert(await self._get_raw(_id))

    async def get_all(self) -> list[AttributeTypeDTO]:
        """Get all Attribute Types."""
        return [
            _convert(attribute_type)
            for attribute_type in await self.__session.scalars(
                select(AttributeType),
            )
        ]

    async def create(self, dto: AttributeTypeDTO) -> None:
        """Create Attribute Type."""
        try:
            attribute_type = AttributeType(
                oid=dto.oid,
                name=dto.name,
                syntax=dto.syntax,
                single_value=dto.single_value,
                no_user_modification=dto.no_user_modification,
                is_system=dto.is_system,
            )
            self.__session.add(attribute_type)
            await self.__session.flush()
        except IntegrityError:
            raise AttributeTypeAlreadyExistsError(
                f"Attribute Type with oid '{dto.oid}' and name"
                + f" '{dto.name}' already exists.",
            )

    async def update(self, _id: int, dto: AttributeTypeDTO) -> None:
        """Update Attribute Type."""
        if dto.is_system:
            raise AttributeTypeCantModifyError(
                "System Attribute Type cannot be modified.",
            )
        attribute_type = await self._get_raw(_id)
        attribute_type.oid = dto.oid
        attribute_type.name = dto.name
        attribute_type.syntax = dto.syntax
        attribute_type.single_value = dto.single_value
        attribute_type.no_user_modification = dto.no_user_modification
        await self.__session.flush()

    async def delete(self, _id: int) -> None:
        """Delete Attribute Type."""
        attribute_type = await self._get_raw(_id)
        await self.__session.delete(attribute_type)
        await self.__session.flush()

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated Attribute Types.

        :param PaginationParams params: page_size and page_number.
        :return PaginationResult: Chunk of Attribute Types and metadata.
        """
        query = build_paginated_search_query(
            model=AttributeType,
            order_by_field=AttributeType.id,
            params=params,
            search_field=AttributeType.name,
        )

        return await PaginationResult[AttributeType].get(
            params=params,
            query=query,
            session=self.__session,
        )

    async def get_one_by_name(
        self,
        attribute_type_name: str,
    ) -> AttributeTypeDTO:
        """Get single Attribute Type by name.

        :param str attribute_type_name: Attribute Type name.
        :raise AttributeTypeNotFoundError: If Attribute Type not found.
        :return AttributeType: Instance of Attribute Type.
        """
        attribute_type = await self.__session.scalar(
            select(AttributeType)
            .where(AttributeType.name == attribute_type_name),
        )  # fmt: skip

        if not attribute_type:
            raise AttributeTypeNotFoundError(
                f"Attribute Type with name '{attribute_type_name}' not found.",
            )

        return _convert(attribute_type)

    async def get_all_by_names(
        self,
        attribute_type_names: list[str] | set[str],
    ) -> list[AttributeTypeDTO]:
        """Get list of Attribute Types by names.

        :param list[str] attribute_type_names: Attribute Type names.
        :return list[AttributeTypeDTO]: List of Attribute Types.
        """
        if not attribute_type_names:
            return []

        query = await self.__session.scalars(
            select(AttributeType)
            .where(AttributeType.name.in_(attribute_type_names)),
        )  # fmt: skip
        return list(map(_convert, query.all()))

    async def delete_all_by_names(
        self,
        attribute_type_names: list[str],
    ) -> None:
        """Delete not system Attribute Types by names.

        :param list[str] attribute_type_names: List of Attribute Types names.
        :return None: None.
        """
        if not attribute_type_names:
            return

        await self.__session.execute(
            delete(AttributeType)
            .where(
                AttributeType.name.in_(attribute_type_names),
                AttributeType.is_system.is_(False),
            ),
        )  # fmt: skip
        await self.__session.flush()
