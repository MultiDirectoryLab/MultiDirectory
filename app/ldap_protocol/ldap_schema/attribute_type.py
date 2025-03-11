"""Attribute Type utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AttributeType


class AttributeTypeSchema(BaseModel):
    """Attribute Type Schema w/o id."""

    oid: str
    name: str
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool


async def create_attribute_type(
    oid: str,
    name: str,
    syntax: str,
    single_value: bool,
    no_user_modification: bool,
    is_system: bool,
    session: AsyncSession,
) -> None:
    """Create a new attribute type.

    :param str oid: OID.
    :param str name: Name.
    :param str syntax: Syntax.
    :param bool single_value: Single value.
    :param bool no_user_modification: No user modification.
    :param bool is_system: Is system.
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


async def get_attribute_type(
    attribute_type_oid: int,
    session: AsyncSession,
) -> AttributeType | None:
    """Get single Attribute Type.

    :param int attribute_type_oid: Attribute Type OID.
    :param AsyncSession session: Database session.
    :return Optional[AccessPolicy]: Attribute Type.
    """
    return await session.get(AttributeType, attribute_type_oid)


async def get_attribute_types(session: AsyncSession) -> list[AttributeType]:
    """Retrieve a list of all attribute types.

    :param AsyncSession session: Database session.
    :return list[AttributeType]: List of attribute types.
    """
    query = await session.scalars(select(AttributeType))
    return list(query.all())


async def modify_attribute_type(
    attribute_type: AttributeType,
    attribute_type_schema: AttributeTypeSchema,
    session: AsyncSession,
) -> None:
    """Modify an attribute type.

    :param AttributeType attribute_type: Attribute Type.
    :param AttributeTypeSchema attribute_type_schema: Attribute Type Schema.
    :param AsyncSession session: Database session.
    :return None.
    """
    attribute_type.oid = attribute_type_schema.oid
    attribute_type.name = attribute_type_schema.name
    attribute_type.syntax = attribute_type_schema.syntax
    attribute_type.single_value = attribute_type_schema.single_value
    attribute_type.no_user_modification = (
        attribute_type_schema.no_user_modification
    )
    attribute_type.is_system = attribute_type_schema.is_system
    await session.flush()


async def delete_attribute_types(
    attribute_types_oids: list[str],
    session: AsyncSession,
) -> None:
    """Delete Attribute Type.

    :param list[str] attribute_types_oids: List of Attribute Types OIDs.
    :param AsyncSession session: Database session.
    :return None: None.
    """
    await session.execute(
        delete(AttributeType)
        .where(AttributeType.oid.in_(attribute_types_oids)),
    )  # fmt: skip
    await session.commit()
