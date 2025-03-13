"""Object Class utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_schema.attribute_type import (
    get_attribute_types_by_names,
)
from models import ObjectClass


class ObjectClassSchema(BaseModel):
    """Object Class Schema."""

    oid: str
    name: str
    superior: str | None
    kind: Literal["STRUCTURAL", "ABSTRACT", "AUXILIARY"]
    is_system: bool
    attribute_types_must: list[str]
    attribute_types_may: list[str]


async def create_object_class(
    oid: str,
    name: str,
    superior: str,
    kind: Literal["STRUCTURAL", "ABSTRACT", "AUXILIARY"],
    is_system: bool,
    attribute_types_must: list[str],
    attribute_types_may: list[str],
    session: AsyncSession,
) -> None:
    """Create a new Object Class.

    :param str oid: OID.
    :param str name: Name.
    :param str superior: Parent Object Class.
    :param Literal["STRUCTURAL", "ABSTRACT", "AUXILIARY"] kind: Kind.
    :param bool is_system: Object Class is system.
    :param list[str] attribute_types_must: Attribute Types must.
    :param list[str] attribute_types_may: Attribute Types may.
    """
    object_class = ObjectClass(
        oid=oid,
        name=name,
        superior=superior,
        kind=kind,
        is_system=is_system,
        attribute_types_must=await get_attribute_types_by_names(
            attribute_types_must,
            session,
        ),
        attribute_types_may=await get_attribute_types_by_names(
            attribute_types_may,
            session,
        ),
    )
    session.add(object_class)
    await session.flush()


async def get_object_class_by_name(
    object_class_name: str,
    session: AsyncSession,
) -> ObjectClass | None:
    """Get single Object Class by name.

    :param str object_class_name: Object Class name.
    :param AsyncSession session: Database session.
    :return ObjectClass: Object Class.
    """
    return await session.get(ObjectClass, object_class_name)


async def get_object_classes_by_names(
    object_class_names: list[str],
    session: AsyncSession,
) -> list[ObjectClass]:
    """Get list of Object Classes by names.

    :param list[str] object_class_names: Object Classes names.
    :param AsyncSession session: Database session.
    :return list[ObjectClass]: List of Object Classes.
    """
    query = await session.scalars(
        select(ObjectClass)
        .where(ObjectClass.name.in_(object_class_names)),
    )  # fmt: skip
    return list(query.all())


async def get_all_object_classes(session: AsyncSession) -> list[ObjectClass]:
    """Retrieve a list of all Object Classes.

    :param AsyncSession session: Database session.
    :return list[ObjectClass]: List of Object Classes.
    """
    query = await session.scalars(
        select(ObjectClass).options(
            selectinload(ObjectClass.attribute_types_must),
            selectinload(ObjectClass.attribute_types_may),
        )
    )
    return list(query.all())


async def modify_object_class(
    request_data: ObjectClassSchema,
    session: AsyncSession,
) -> None:
    """Modify Object Class.

    :param AsyncSession session: Database session.
    :return None.
    """
    # TODO: Implement this function.


async def delete_object_classes_by_names(
    object_classes_names: list[str],
    session: AsyncSession,
) -> None:
    """Delete Object Classes by Names.

    :param list[str] object_classes_names: Object classes names.
    :param AsyncSession session: Database session.
    :return None.
    """
    await session.execute(
        delete(ObjectClass)
        .where(ObjectClass.name.in_(object_classes_names)),
    )  # fmt: skip
    await session.commit()
