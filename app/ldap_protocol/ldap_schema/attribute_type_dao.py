"""Attribute Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import P
from adaptix.conversion import get_converter, link_function
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

_convert_model_to_dto = get_converter(AttributeType, AttributeTypeDTO)
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


class AttributeTypeDAO(AbstractDAO[AttributeTypeDTO, str]):
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

    async def get(self, _id: str) -> AttributeTypeDTO:
        """Get Attribute Type by id."""
        return _convert_model_to_dto(await self._get_one_raw_by_name(_id))

    async def get_all(self) -> list[AttributeTypeDTO]:
        """Get all Attribute Types."""
        return [
            _convert_model_to_dto(attribute_type)
            for attribute_type in await self.__session.scalars(
                select(AttributeType),
            )
        ]

    async def create(self, dto: AttributeTypeDTO) -> None:
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

    async def update(self, _id: str, dto: AttributeTypeDTO) -> None:
        """Update Attribute Type.

        NOTE: Only 3 attrs can be updated.
        """
        obj = await self._get_one_raw_by_name(_id)

        if obj.is_system:
            raise AttributeTypeCantModifyError(
                "System Attribute Type cannot be modified.",
            )

        obj.syntax = dto.syntax
        obj.single_value = dto.single_value
        obj.no_user_modification = dto.no_user_modification

        await self.__session.flush()

    async def delete(self, _id: str) -> None:
        """Delete Attribute Type."""
        attribute_type = await self._get_one_raw_by_name(_id)
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

    async def _get_one_raw_by_name(
        self,
        name: str,
    ) -> AttributeType:
        attribute_type = await self.__session.scalar(
            select(AttributeType)
            .filter_by(name=name),
        )  # fmt: skip

        if not attribute_type:
            raise AttributeTypeNotFoundError(
                f"Attribute Type with name '{name}' not found.",
            )
        return attribute_type

    async def get_all_by_names(
        self,
        names: list[str] | set[str],
    ) -> list[AttributeTypeDTO]:
        """Get list of Attribute Types by names.

        :param list[str] names: Attribute Type names.
        :return list[AttributeTypeDTO]: List of Attribute Types.
        """
        if not names:
            return []

        query = await self.__session.scalars(
            select(AttributeType)
            .where(AttributeType.name.in_(names)),
        )  # fmt: skip
        return list(map(_convert_model_to_dto, query.all()))

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete not system Attribute Types by names.

        :param list[str] names: List of Attribute Types names.
        :return None: None.
        """
        if not names:
            return

        await self.__session.execute(
            delete(AttributeType)
            .where(
                AttributeType.name.in_(names),
                AttributeType.is_system.is_(False),
            ),
        )  # fmt: skip
        await self.__session.flush()
