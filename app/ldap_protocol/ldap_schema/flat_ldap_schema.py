"""API for LDAP Schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from models import AttributeType, ObjectClass


async def get_flat_ldap_schema(
    session: AsyncSession,
) -> dict[str, tuple[list[AttributeType], list[AttributeType], int]]:
    """Return the LDAP schema.

    :return: The LDAP schema.
    """
    # 0 init
    flat_schema: dict[str, tuple[list, list, int]] = dict()
    object_class_names: list[str] = []
    depth: int = 0

    # 1 calc root object classes
    query = (
        select(ObjectClass)
        .where(
            ObjectClass.superior_name.is_(None),
        )
        .options(
            selectinload(ObjectClass.attribute_types_must),
            selectinload(ObjectClass.attribute_types_may),
        )
    )
    result = await session.scalars(query)
    object_classes = list(result.all())

    for object_class in object_classes:
        flat_schema[object_class.name] = (
            object_class.attribute_types_must,
            object_class.attribute_types_may,
            depth,
        )
        object_class_names.append(object_class.name)

    # 2 while loop
    while True:
        depth += 1
        # 3 query
        query = (
            select(ObjectClass)
            .where(
                ObjectClass.superior_name.in_(object_class_names),
                ObjectClass.name.notin_(object_class_names),
            )
            .options(
                selectinload(ObjectClass.attribute_types_must),
                selectinload(ObjectClass.attribute_types_may),
            )
        )
        result = await session.scalars(query)
        object_classes = list(result.all())

        # 4 check
        if not object_classes:
            break

        # 5 extend schema
        object_class_names.extend(
            [object_class.name for object_class in object_classes]
        )
        for object_class in object_classes:
            attrs_must = object_class.attribute_types_must[:]
            attrs_may = object_class.attribute_types_may[:]

            if object_class.superior_name:
                attrs_must.extend(flat_schema[object_class.superior_name][0])
                attrs_may.extend(flat_schema[object_class.superior_name][1])

            flat_schema[object_class.name] = (
                attrs_must,
                attrs_may,
                depth,
            )

    return flat_schema


async def get_attribute_type_names_by_object_class_names(
    session: AsyncSession,
    object_class_names: list[str] | set[str],
) -> tuple[set[str], set[str]]:
    """Return the attribute types by object class name.

    :return: The attribute types by object class name.
    """
    flat_ldap_schema = await get_flat_ldap_schema(session)
    flat_object_classes = [
        tpl
        for name, tpl in flat_ldap_schema.items()
        if name in object_class_names
    ]

    if len(flat_object_classes) != len(object_class_names):
        raise ValueError(
            "Not all object class names are present in the schema."
        )

    res_attribute_type_names_must: set[str] = set()
    res_attribute_type_names_may: set[str] = set()

    for attribute_types_must, attribute_types_may, _ in flat_object_classes:
        attribute_type_names_must = {
            attribute_type.name for attribute_type in attribute_types_must
        }
        res_attribute_type_names_must.update(attribute_type_names_must)

        attribute_type_names_may = {
            attribute_type.name for attribute_type in attribute_types_may
        }
        res_attribute_type_names_may.update(attribute_type_names_may)

    attribute_type_names_may -= attribute_type_names_must
    return (res_attribute_type_names_must, res_attribute_type_names_may)
