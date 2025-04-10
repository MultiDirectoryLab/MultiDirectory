"""API for LDAP Schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pprint

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from models import ObjectClass


async def get_flat_ldap_schema(
    session: AsyncSession,
) -> dict[str, tuple[list, list, int]]:
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
        pprint.pprint(depth)
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

    # await session.commit()
    return flat_schema
