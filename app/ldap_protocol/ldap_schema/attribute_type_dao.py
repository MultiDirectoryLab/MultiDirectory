"""Attribute Type DAO.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.exceptions import (
    InstanceCantModifyError,
    InstanceNotFoundError,
)
from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    PaginationParams,
    PaginationResult,
    build_paginated_search_query,
)
from models import AttributeType


class AttributeTypeSchema(BaseModel):
    """Attribute Type Schema."""

    oid: str
    name: str
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool


class AttributeTypeUpdateSchema(BaseModel):
    """Attribute Type Schema for modify/update."""

    syntax: str
    single_value: bool
    no_user_modification: bool


class AttributeTypePaginationSchema(BasePaginationSchema[AttributeTypeSchema]):
    """Attribute Type Schema with pagination result."""

    items: list[AttributeTypeSchema]


class AttributeTypeDAO:
    """Attribute Type DAO."""

    __session: AsyncSession
    AttributeTypeNotFoundError = InstanceNotFoundError
    AttributeTypeCantModifyError = InstanceCantModifyError

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Attribute Type DAO with session."""
        self.__session = session

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

    async def create_one(
        self,
        oid: str,
        name: str,
        syntax: str,
        single_value: bool,
        no_user_modification: bool,
        is_system: bool,
    ) -> None:
        """Create a new Attribute Type.

        :param str oid: OID.
        :param str name: Name.
        :param str syntax: Syntax.
        :param bool single_value: Single value.
        :param bool no_user_modification: User can't modify it.
        :param bool is_system: Attribute Type is system.
        :return None.
        """
        attribute_type = AttributeType(
            oid=oid,
            name=name,
            syntax=syntax,
            single_value=single_value,
            no_user_modification=no_user_modification,
            is_system=is_system,
        )
        self.__session.add(attribute_type)

    async def get_one_by_name(
        self,
        attribute_type_name: str,
    ) -> AttributeType:
        """Get single Attribute Type by name.

        :param str attribute_type_name: Attribute Type name.
        :raise AttributeTypeNotFoundError: If Attribute Type not found.
        :return AttributeType: Instance of Attribute Type.
        """
        attribute_type = await self.__session.scalar(
            select(AttributeType)
            .where(AttributeType.name == attribute_type_name)
        )  # fmt: skip

        if not attribute_type:
            raise self.AttributeTypeNotFoundError(
                f"Attribute Type with name '{attribute_type_name}' not found."
            )

        return attribute_type

    async def get_all_by_names(
        self,
        attribute_type_names: list[str] | set[str],
    ) -> list[AttributeType]:
        """Get list of Attribute Types by names.

        :param list[str] attribute_type_names: Attribute Type names.
        :return list[AttributeType]: List of Attribute Types.
        """
        if not attribute_type_names:
            return []

        query = await self.__session.scalars(
            select(AttributeType)
            .where(AttributeType.name.in_(attribute_type_names)),
        )  # fmt: skip
        return list(query.all())

    async def modify_one(
        self,
        attribute_type: AttributeType,
        new_statement: AttributeTypeUpdateSchema,
    ) -> None:
        """Modify Attribute Type.

        :param AttributeType attribute_type: Attribute Type.
        :param AttributeTypeUpdateSchema new_statement: Attribute Type Schema.
        :raise AttributeTypeCantModifyError: If Attribute Type is system,\
            it cannot be changed.
        :return None.
        """
        if attribute_type.is_system:
            raise self.AttributeTypeCantModifyError(
                "System Attribute Type cannot be modified."
            )

        attribute_type.syntax = new_statement.syntax
        attribute_type.single_value = new_statement.single_value
        attribute_type.no_user_modification = (
            new_statement.no_user_modification
        )

    async def delete_all_by_names(
        self,
        attribute_type_names: list[str],
    ) -> None:
        """Delete not system Attribute Types by names.

        :param list[str] attribute_type_names: List of Attribute Types names.
        :param AsyncSession session: Database session.
        :return None: None.
        """
        if not attribute_type_names:
            return None

        await self.__session.execute(
            delete(AttributeType)
            .where(
                AttributeType.name.in_(attribute_type_names),
                AttributeType.is_system.is_(False),
            ),
        )  # fmt: skip
