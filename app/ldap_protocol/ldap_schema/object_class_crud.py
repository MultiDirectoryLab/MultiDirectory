"""Object Class utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_schema.attribute_type_crud import (
    get_attribute_types_by_names,
)
from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    BaseSchemaModel,
    PaginationParams,
    PaginationResult,
)
from models import Entry, KindType, ObjectClass

OBJECT_CLASS_KINDS_ALLOWED: tuple[KindType, ...] = (
    "STRUCTURAL",
    "ABSTRACT",
    "AUXILIARY",
)


class ObjectClassSchema(BaseSchemaModel):
    """Object Class Schema."""

    oid: str
    name: str
    superior_name: str | None
    kind: KindType
    is_system: bool
    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]

    @classmethod
    def from_db(cls, object_class: ObjectClass) -> "ObjectClassSchema":
        """Create an instance of Object Class Schema from database."""
        return cls(
            oid=object_class.oid,
            name=object_class.name,
            superior_name=object_class.superior_name,
            kind=object_class.kind,
            is_system=object_class.is_system,
            attribute_type_names_must=object_class.attribute_type_names_must,
            attribute_type_names_may=object_class.attribute_type_names_may,
        )


class ObjectClassPaginationSchema(BasePaginationSchema[ObjectClassSchema]):
    """Object Class Schema with pagination result."""

    items: list[ObjectClassSchema]


async def get_object_classes_paginator(
    params: PaginationParams,
    session: AsyncSession,
) -> PaginationResult:
    """Retrieve paginated object_classes.

    :param PaginationParams params: page_size and page_number.
    :param AsyncSession session: Database session.
    :return PaginationResult: Chunk of object_classes and metadata.
    """
    return await PaginationResult[ObjectClass].get(
        params=params,
        query=select(ObjectClass).order_by(ObjectClass.id),
        sqla_model=ObjectClass,
        session=session,
    )


class ObjectClassUpdateSchema(BaseModel):
    """Object Class Schema for modify/update."""

    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]


async def create_object_class(
    oid: str,
    name: str,
    superior_name: str | None,
    kind: KindType,
    is_system: bool,
    attribute_type_names_must: list[str],
    attribute_type_names_may: list[str],
    session: AsyncSession,
) -> None:
    """Create a new Object Class.

    :param str oid: OID.
    :param str name: Name.
    :param str | None superior_name: Parent Object Class.
    :param KindType kind: Kind.
    :param bool is_system: Object Class is system.
    :param list[str] attribute_type_names_must: Attribute Types must.
    :param list[str] attribute_type_names_may: Attribute Types may.
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
        for name in attribute_type_names_may
        if name not in attribute_type_names_must
    ]
    object_class = ObjectClass(
        oid=oid,
        name=name,
        superior=superior,
        kind=kind,
        is_system=is_system,
        attribute_types_must=await get_attribute_types_by_names(
            attribute_type_names_must,
            session,
        ),
        attribute_types_may=await get_attribute_types_by_names(
            attribute_types_may_filtered,
            session,
        ),
    )
    session.add(object_class)


async def count_exists_object_class_by_names(
    object_class_names: list[str],
    session: AsyncSession,
) -> int:
    """Count exists ObjectClass by names."""
    count_query = (
        select(func.count())
        .select_from(ObjectClass)
        .where(ObjectClass.name.in_(object_class_names))
    )
    result = await session.scalars(count_query)
    return result.one()


async def is_all_object_classes_exists(
    object_class_names: list[str],
    session: AsyncSession,
) -> bool:
    """Check if all Object Classes exist."""
    count_exists_object_classes = await count_exists_object_class_by_names(
        object_class_names,
        session,
    )

    return bool(count_exists_object_classes == len(object_class_names))


async def get_object_class_by_name(
    object_class_name: str,
    session: AsyncSession,
) -> ObjectClass | None:
    """Get single Object Class by name.

    :param str object_class_name: Object Class name.
    :param AsyncSession session: Database session.
    :return ObjectClass | None: Object Class.
    """
    return await session.scalar(
        select(ObjectClass)
        .where(ObjectClass.name == object_class_name)
    )  # fmt: skip


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
            new_statement.attribute_type_names_must,
            session,
        ),
    )

    attribute_types_may_filtered = [
        name
        for name in new_statement.attribute_type_names_may
        if name not in new_statement.attribute_type_names_must
    ]
    object_class.attribute_types_may.clear()
    object_class.attribute_types_may.extend(
        await get_attribute_types_by_names(
            attribute_types_may_filtered,
            session,
        ),
    )


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
            ~ObjectClass.name.in_(
                select(func.unnest(Entry.object_class_names))
                .where(Entry.object_class_names.isnot(None))
            ),
        ),
    )  # fmt: skip
