"""Object Class utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Literal

from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_schema.attribute_type_crud import (
    get_attribute_types_by_names,
)
from ldap_protocol.utils.helpers import PaginationResult, get_pagination
from models import ObjectClass

type KindType = Literal["STRUCTURAL", "ABSTRACT", "AUXILIARY"]

OBJECT_CLASS_KINDS_ALLOWED: tuple[KindType, ...] = (
    "STRUCTURAL",
    "ABSTRACT",
    "AUXILIARY",
)


class ObjectClassSchema(BaseModel):
    """Object Class Schema."""

    oid: str
    name: str
    superior_name: str | None
    kind: KindType
    is_system: bool
    attribute_types_must: list[str]
    attribute_types_may: list[str]

    @classmethod
    def from_db(cls, object_class: ObjectClass) -> "ObjectClassSchema":
        """Create an instance from database."""
        return cls(
            oid=object_class.oid,
            name=object_class.name,
            superior_name=object_class.superior_name,
            kind=object_class.kind,
            is_system=object_class.is_system,
            attribute_types_must=object_class.attribute_types_must_display,
            attribute_types_may=object_class.attribute_types_may_display,
        )


async def get_object_classes_paginator(
    session: AsyncSession,
    page_number: int,
    page_size: int,
) -> PaginationResult:
    """Retrieve paginated object_classes.

    :param AsyncSession session: Database session.
    :param int page_number: Current page number.
    :return Paginator: Paginated result with object_classes and metadata.
    """
    if page_number < 1:
        raise ValueError("Page number must be greater than 0.")

    return await get_pagination(
        page_size=page_size,
        page_number=page_number,
        query=select(ObjectClass).order_by(ObjectClass.name),
        sqla_model=ObjectClass,
        schema_model=ObjectClassSchema,
        session=session,
    )


class ObjectClassUpdateSchema(BaseModel):
    """Object Class Schema for modify/update."""

    attribute_types_must: list[str]
    attribute_types_may: list[str]


async def create_object_class(
    oid: str,
    name: str,
    superior_name: str | None,
    kind: KindType,
    is_system: bool,
    attribute_types_must: list[str],
    attribute_types_may: list[str],
    session: AsyncSession,
) -> None:
    """Create a new Object Class.

    :param str oid: OID.
    :param str name: Name.
    :param str | None superior_name: Parent Object Class.
    :param KindType kind: Kind.
    :param bool is_system: Object Class is system.
    :param list[str] attribute_types_must: Attribute Types must.
    :param list[str] attribute_types_may: Attribute Types may.
    :param AsyncSession session: Database session.
    :return None.
    """
    if kind not in OBJECT_CLASS_KINDS_ALLOWED:
        raise ValueError(f"Object class kind is not valid: {kind}.")

    superior = (
        await get_object_class_by_name(superior_name, session)
        if superior_name
        else None
    )
    if superior_name and not superior:
        raise ValueError(
            f"Superior Object class {superior_name} not found in schema."
        )

    attribute_types_may_filtered = [
        name
        for name in attribute_types_may
        if name not in attribute_types_must
    ]
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
            attribute_types_may_filtered,
            session,
        ),
    )
    session.add(object_class)
    await session.commit()


async def get_object_class_by_name(
    object_class_name: str,
    session: AsyncSession,
) -> ObjectClass | None:
    """Get single Object Class by name.

    :param str object_class_name: Object Class name.
    :param AsyncSession session: Database session.
    :return ObjectClass | None: Object Class.
    """
    return await session.get(ObjectClass, object_class_name)


async def get_object_classes_by_names(
    object_class_names: list[str] | set[str],
    session: AsyncSession,
) -> list[ObjectClass]:
    """Get list of Object Classes by names.

    :param list[str] object_class_names: Object Classes names.
    :param AsyncSession session: Database session.
    :return list[ObjectClass]: List of Object Classes.
    """
    query = await session.scalars(
        select(ObjectClass)
        .where(ObjectClass.name.in_(object_class_names))
        .options(
            selectinload(ObjectClass.attribute_types_must),
            selectinload(ObjectClass.attribute_types_may),
        )
    )  # fmt: skip
    return list(query.all())


async def modify_object_class(
    object_class: ObjectClass,
    new_statement: ObjectClassUpdateSchema,
    session: AsyncSession,
) -> None:
    """Modify Object Class.

    :param ObjectClass object_class: Object Class.
    :param ObjectClassUpdateSchema new_statement: New statement of object class
    :param AsyncSession session: Database session.
    :return None.
    """
    object_class.attribute_types_must.clear()
    object_class.attribute_types_must.extend(
        await get_attribute_types_by_names(
            new_statement.attribute_types_must,
            session,
        ),
    )

    attribute_types_may_filtered = [
        name
        for name in new_statement.attribute_types_may
        if name not in new_statement.attribute_types_must
    ]
    object_class.attribute_types_may.clear()
    object_class.attribute_types_may.extend(
        await get_attribute_types_by_names(
            attribute_types_may_filtered,
            session,
        ),
    )
    await session.commit()


async def delete_object_classes_by_names(
    object_classes_names: list[str],
    session: AsyncSession,
) -> None:
    """Delete not system Object Classes by Names.

    :param list[str] object_classes_names: Object classes names.
    :param AsyncSession session: Database session.
    :return None.
    """
    await session.execute(
        delete(ObjectClass)
        .where(
            ObjectClass.name.in_(object_classes_names),
            ObjectClass.is_system.is_(False),
        ),
    )  # fmt: skip
    await session.commit()
