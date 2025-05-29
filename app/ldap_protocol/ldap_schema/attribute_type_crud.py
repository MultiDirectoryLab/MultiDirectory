"""Attribute Type utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    BaseSchemaModel,
    PaginationParams,
    PaginationResult,
)
from models import AttributeType


class AttributeTypeSchema(BaseSchemaModel):
    """Attribute Type Schema."""

    oid: str
    name: str
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool

    @classmethod
    def from_db(cls, attribute_type: AttributeType) -> "AttributeTypeSchema":
        """Create an instance of Attribute Type Schema from database."""
        return cls(
            oid=attribute_type.oid,
            name=attribute_type.name,
            syntax=attribute_type.syntax,
            single_value=attribute_type.single_value,
            no_user_modification=attribute_type.no_user_modification,
            is_system=attribute_type.is_system,
        )


class AttributeTypeUpdateSchema(BaseModel):
    """Attribute Type Schema for modify/update."""

    syntax: str
    single_value: bool
    no_user_modification: bool


class AttributeTypePaginationSchema(BasePaginationSchema[AttributeTypeSchema]):
    """Attribute Type Schema with pagination result."""

    items: list[AttributeTypeSchema]


class AttributeTypeDAO:
    """Attribute Type manager."""

    _session: AsyncSession

    def __init__(self, session: AsyncSession) -> None:
        """Initialize Attribute Type DAO with session."""
        self._session = session

    async def get_attribute_types_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Retrieve paginated attribute_types.

        :param PaginationParams params: page_size and page_number.
        :return PaginationResult: Chunk of attribute_types and metadata.
        """
        return await PaginationResult[AttributeType].get(
            params=params,
            query=select(AttributeType).order_by(AttributeType.id),
            sqla_model=AttributeType,
            session=self._session,
        )

    async def create_attribute_type(
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
        self._session.add(attribute_type)

    async def get_attribute_type_by_name(
        self,
        attribute_type_name: str,
    ) -> AttributeType | None:
        """Get single Attribute Type by name.

        :param str attribute_type_name: Attribute Type name.
        :return AttributeType | None: Attribute Type.
        """
        return await self._session.scalar(
            select(AttributeType)
            .where(AttributeType.name == attribute_type_name)
        )  # fmt: skip

    async def get_attribute_types_by_names(
        self,
        attribute_type_names: list[str] | set[str],
    ) -> list[AttributeType]:
        """Get list of Attribute Types by names.

        :param list[str] attribute_type_names: Attribute Type names.
        :return list[AttributeType]: List of Attribute Types.
        """
        if not attribute_type_names:
            return []

        query = await self._session.scalars(
            select(AttributeType)
            .where(AttributeType.name.in_(attribute_type_names)),
        )  # fmt: skip
        return list(query.all())


async def modify_attribute_type(
    attribute_type: AttributeType,
    new_statement: AttributeTypeUpdateSchema,
) -> None:
    """Modify Attribute Type.

    :param AttributeType attribute_type: Attribute Type.
    :param AttributeTypeUpdateSchema new_statement: Attribute Type Schema.
    :param AsyncSession session: Database session.
    :return None.
    """
    attribute_type.syntax = new_statement.syntax
    attribute_type.single_value = new_statement.single_value
    attribute_type.no_user_modification = new_statement.no_user_modification


async def delete_attribute_types_by_names(
    attribute_type_names: list[str],
    session: AsyncSession,
) -> None:
    """Delete not system Attribute Types by names.

    :param list[str] attribute_type_names: List of Attribute Types OIDs.
    :param AsyncSession session: Database session.
    :return None: None.
    """
    if not attribute_type_names:
        return None

    await session.execute(
        delete(AttributeType)
        .where(
            AttributeType.name.in_(attribute_type_names),
            AttributeType.is_system.is_(False),
        ),
    )  # fmt: skip
