"""Object Class utils.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel
from sqlalchemy import delete, select
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
from models import KindType, ObjectClass

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
        """Create an instance from database.

        Args:
            object_class (ObjectClass): source

        Returns:
            ObjectClassSchema: instance of ObjectClassSchema.
        """
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
    """Attribute Type Schema with pagination result."""

    items: list[ObjectClassSchema]


async def get_object_classes_paginator(
    params: PaginationParams,
    session: AsyncSession,
) -> PaginationResult:
    """Retrieve paginated object_classes.

    Args:
        params (PaginationParams): page_size and page_number.
        session (AsyncSession): Database session.

    Returns:
        PaginationResult: Chunk of object_classes and metadata.
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

    Args:
        oid (str): OID.
        name (str): Name.
        superior_name (str | None): Parent Object Class.
        kind (KindType): Kind.
        is_system (bool): Object Class is system.
        attribute_type_names_must (list[str]): Attribute Types must.
        attribute_type_names_may (list[str]): Attribute Types may.
        session (AsyncSession): Database session.

    Raises:
        ValueError: kind is not valid
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
    await session.commit()


async def get_object_class_by_name(
    object_class_name: str,
    session: AsyncSession,
) -> ObjectClass | None:
    """Get single Object Class by name.

    Args:
        object_class_name (str): Object Class name.
        session (AsyncSession): Database session.

    Returns:
        ObjectClass | None: Object Class.
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

    Args:
        object_class_names (list[str]): Object Classes names.
        session (AsyncSession): Database session.

    Returns:
        list[ObjectClass]: List of Object Classes.
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

    Args:
        object_class (ObjectClass): Object Class.
        new_statement (ObjectClassUpdateSchema): New statement of object
            class
        session (AsyncSession): Database session.
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
    await session.commit()


async def delete_object_classes_by_names(
    object_classes_names: list[str],
    session: AsyncSession,
) -> None:
    """Delete not system Object Classes by Names.

    Args:
        object_classes_names (list[str]): Object classes names.
        session (AsyncSession): Database session.
    """
    await session.execute(
        delete(ObjectClass)
        .where(
            ObjectClass.name.in_(object_classes_names),
            ObjectClass.is_system.is_(False),
        ),
    )  # fmt: skip
    await session.commit()
