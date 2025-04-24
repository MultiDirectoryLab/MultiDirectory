"""Attribute Type utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

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

    :param str oid: OID.
    :param str name: Name.
    :param str syntax: Syntax.
    :param bool single_value: Single value.
    :param bool no_user_modification: User can't modify it.
    :param bool is_system: Attribute Type is system.
    :param AsyncSession session: Database session.
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
    session.add(attribute_type)
    await session.flush()


async def get_attribute_type_by_name(
    attribute_type_name: str,
    session: AsyncSession,
) -> AttributeType | None:
    """Get single Attribute Type by name.

    :param str attribute_type_name: Attribute Type name.
    :param AsyncSession session: Database session.
    :return AttributeType | None: Attribute Type.
    """
    return await session.get(AttributeType, attribute_type_name)


async def get_attribute_types_by_names(
    attribute_type_names: list[str] | set[str],
    session: AsyncSession,
) -> list[AttributeType]:
    """Get list of Attribute Types by names.

    :param list[str] attribute_type_names: Attribute Type names.
    :param AsyncSession session: Database session.
    :return list[AttributeType]: List of Attribute Types.
    """
    if not attribute_type_names:
        return []

    query = await session.scalars(
        select(AttributeType)
        .where(AttributeType.name.in_(attribute_type_names)),
    )  # fmt: skip
    return list(query.all())


async def get_all_attribute_types(
    session: AsyncSession,
) -> list[AttributeType]:
    """Retrieve a list of all Attribute Types.

    :param AsyncSession session: Database session.
    :return list[AttributeType]: List of Attribute Types.
    """
    result = await session.scalars(select(AttributeType))
    return list(result.all())


async def modify_attribute_type(
    attribute_type: AttributeType,
    new_statement: AttributeTypeUpdateSchema,
    session: AsyncSession,
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
    await session.commit()


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
    await session.commit()
