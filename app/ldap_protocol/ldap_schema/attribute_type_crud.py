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
        """Create an instance from database.

        Args:
            attribute_type (AttributeType): instance of AttributeType

        Returns:
            AttributeTypeSchema: serialized AttributeType.
        """
        return cls(
            oid=attribute_type.oid,
            name=attribute_type.name,
            syntax=attribute_type.syntax,
            single_value=attribute_type.single_value,
            no_user_modification=attribute_type.no_user_modification,
            is_system=attribute_type.is_system,
        )


class AttributeTypePaginationSchema(BasePaginationSchema[AttributeTypeSchema]):
    """Attribute Type Schema with pagination result."""

    items: list[AttributeTypeSchema]


async def get_attribute_types_paginator(
    params: PaginationParams,
    session: AsyncSession,
) -> PaginationResult:
    """Retrieve paginated attribute_types.

    Args:
        params (PaginationParams): page_size and page_number.
        session (AsyncSession): Database session.

    Returns:
        PaginationResult: Chunk of attribute_types and metadata.
    """
    return await PaginationResult[AttributeType].get(
        params=params,
        query=select(AttributeType).order_by(AttributeType.id),
        sqla_model=AttributeType,
        session=session,
    )


class AttributeTypeUpdateSchema(BaseModel):
    """Attribute Type Schema for modify/update."""

    syntax: str
    single_value: bool
    no_user_modification: bool


async def create_attribute_type(
    oid: str,
    name: str,
    syntax: str,
    single_value: bool,
    no_user_modification: bool,
    is_system: bool,
    session: AsyncSession,
) -> None:
    """Create a new Attribute Type.

    Args:
        oid (str): OID.
        name (str): Name.
        syntax (str): Syntax.
        single_value (bool): Single value.
        no_user_modification (bool): User can't modify it.
        is_system (bool): Attribute Type is system.
        session (AsyncSession): Database session.
    """
    attribute_type = AttributeType(
        oid=oid,
        name=name,
        syntax=syntax,
        single_value=single_value,
        no_user_modification=no_user_modification,
        is_system=is_system,
    )
    session.add(attribute_type)
    await session.commit()


async def get_attribute_type_by_name(
    attribute_type_name: str,
    session: AsyncSession,
) -> AttributeType | None:
    """Get single Attribute Type by name.

    Args:
        attribute_type_name (str): Attribute Type name.
        session (AsyncSession): Database session.

    Returns:
        AttributeType | None: Attribute Type.
    """
    return await session.scalar(
        select(AttributeType)
        .where(AttributeType.name == attribute_type_name)
    )  # fmt: skip


async def get_attribute_types_by_names(
    attribute_type_names: list[str] | set[str],
    session: AsyncSession,
) -> list[AttributeType]:
    """Get list of Attribute Types by names.

    Args:
        attribute_type_names (list[str]): Attribute Type names.
        session (AsyncSession): Database session.

    Returns:
        list[AttributeType]: List of Attribute Types.
    """
    if not attribute_type_names:
        return []

    query = await session.scalars(
        select(AttributeType)
        .where(AttributeType.name.in_(attribute_type_names)),
    )  # fmt: skip
    return list(query.all())


async def modify_attribute_type(
    attribute_type: AttributeType,
    new_statement: AttributeTypeUpdateSchema,
    session: AsyncSession,
) -> None:
    """Modify Attribute Type.

    Args:
        attribute_type (AttributeType): Attribute Type.
        new_statement (AttributeTypeUpdateSchema): Attribute Type
            Schema.
        session (AsyncSession): Database session.
    """
    attribute_type.syntax = new_statement.syntax
    attribute_type.single_value = new_statement.single_value
    attribute_type.no_user_modification = new_statement.no_user_modification
    await session.commit()


async def delete_attribute_types_by_names(
    attribute_type_names: list[str],
    session: AsyncSession,
) -> None:
    """Delete not system Attribute Types by names.

    Args:
        attribute_type_names (list[str]): List of Attribute Types OIDs.
        session (AsyncSession): Database session.
    """
    if not attribute_type_names:
        return

    await session.execute(
        delete(AttributeType)
        .where(
            AttributeType.name.in_(attribute_type_names),
            AttributeType.is_system.is_(False),
        ),
    )  # fmt: skip
    await session.commit()
