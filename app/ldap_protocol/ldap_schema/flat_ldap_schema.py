"""API for LDAP Schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_schema.object_class_crud import (
    get_all_object_classes,
    get_object_class_by_name,
)
from models import ObjectClass


# fmt: off
async def get_recursion_schema(session: AsyncSession) -> None:
    """Return the LDAP schema.

    :return: The LDAP schema.
    """
    object_classes_list = await get_all_object_classes(session)
    object_classes_dict = {
        object_class.name: object_class
        for object_class in object_classes_list
    }

    result: dict[str, tuple[list, list]] = dict()
    result["top"] = (
        object_classes_dict["top"].attribute_types_must,
        object_classes_dict["top"].attribute_types_may,
    )  # default

    for _, object_class in object_classes_dict.items():
        attrs_must = object_class.attribute_types_must
        attrs_may = object_class.attribute_types_may

        if object_class.superior_name:
            if object_class.superior_name in result:
                attrs_must.extend(result[object_class.name][0])
                attrs_may.extend(result[object_class.name][1])

            else:
                sup1 = object_classes_dict[object_class.superior_name]
                attrs_must.extend(sup1.attribute_types_must)
                attrs_may.extend(sup1.attribute_types_may)

                if sup1.superior_name:
                    if sup1.superior_name in result:
                        attrs_must.extend(result[sup1.superior_name][0])
                        attrs_may.extend(result[sup1.superior_name][1])

                    else:
                        sup2 = object_classes_dict[sup1.superior_name]
                        attrs_must.extend(sup2.attribute_types_must)
                        attrs_may.extend(sup2.attribute_types_may)

                        if sup2.superior_name:
                            if sup2.superior_name in result:
                                attrs_must.extend(result[sup2.superior_name][0])
                                attrs_may.extend(result[sup2.superior_name][1])

                            else:
                                sup3 = object_classes_dict[sup2.superior_name]
                                attrs_must.extend(sup3.attribute_types_must)
                                attrs_may.extend(sup3.attribute_types_may)

        result[object_class.name] = (attrs_must, attrs_may)
# fmt: on


async def get_flat_ldap_schema(
    session: AsyncSession,
) -> dict[str, tuple[list, list]]:
    """Return the LDAP schema.

    :return: The LDAP schema.
    """
    # 0 init
    flat_schema: dict[str, tuple[list, list]] = dict()

    # 1 default
    # RFC 4512 p.2.4 (Object Classes):
    # "All object classes, either structural, auxiliary, or abstract,
    # are required to inherit from the 'top' object class, either directly
    # or indirectly."
    object_class_top = await get_object_class_by_name("top", session)
    flat_schema["top"] = (
        object_class_top.attribute_types_must,
        object_class_top.attribute_types_may,
    )
    object_class_names: list[str] = ["top"]

    # 2 while loop
    while True:
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
            attrs_must = object_class.attribute_types_must
            attrs_may = object_class.attribute_types_may

            if object_class.superior_name:
                attrs_must.extend(flat_schema[object_class.superior_name][0])
                attrs_may.extend(flat_schema[object_class.superior_name][1])

            flat_schema[object_class.name] = (
                attrs_must,
                attrs_may,
            )
    return flat_schema
