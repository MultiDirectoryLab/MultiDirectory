"""API for LDAP Schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from collections import defaultdict
from typing import Any, Iterable, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_schema.object_class_crud import (
    get_object_classes_by_names,
)
from models import AttributeType, Directory, ObjectClass


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
                parent_object_class = flat_schema[object_class.superior_name]
                attrs_must.extend(parent_object_class[0])
                attrs_may.extend(parent_object_class[1])

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

    flat_object_classes = []
    for object_class_name in object_class_names:
        flat_object_class = flat_ldap_schema.get(object_class_name)
        if flat_object_class is None:
            raise ValueError(
                f"Object class {object_class_name} not found in schema."
            )
        else:
            flat_object_classes.append(flat_object_class)

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


async def get_structural_object_class_names(
    session: AsyncSession,
    object_class_names: set[str],
) -> list[str]:
    """Check if object class names contains structural object class."""
    object_classes = await get_object_classes_by_names(
        object_class_names,
        session,
    )
    object_class: ObjectClass

    structural_object_class_names = []
    for object_class in object_classes:
        if object_class.is_structural:
            structural_object_class_names.append(object_class.name)

    return structural_object_class_names


class PartialI(Protocol):
    """Attribute interface."""

    name: str
    values: list[str | bytes]

    # @property
    # def name(self) -> str: ...

    # @property
    # def values(self) -> list[str | bytes]: ...


async def apply_ldap_schema(
    session: AsyncSession,
    new_dir: Directory,
    attributes: Iterable[PartialI],
    object_class_names: set[str],
) -> tuple[Any | dict[Any, list[str]], list, list]:
    """Apply the LDAP schema to the directory."""
    (
        _ldap_schema_must_field_names,
        _ldap_schema_may_field_names,
    ) = await get_attribute_type_names_by_object_class_names(
        session,
        object_class_names,
    )
    _errors: dict[LDAPCodes, list[str]] = defaultdict(list)
    dropped_attributes: list[PartialI] = []
    permitted_attributes: list[PartialI] = []
    must_field_names_used: set[str] = set()

    for attribute in attributes:
        if attribute.name in _ldap_schema_must_field_names:
            permitted_attributes.append(attribute)
            must_field_names_used.add(attribute.name)
            if not attribute.values:
                _errors[LDAPCodes.INVALID_ATTRIBUTE_SYNTAX].append(
                    f"Attribute {attribute} must have a value;"
                )
        elif attribute.name in _ldap_schema_may_field_names:
            permitted_attributes.append(attribute)
        else:
            dropped_attributes.append(attribute)

    empty = _ldap_schema_must_field_names - must_field_names_used
    if empty:
        _errors[LDAPCodes.OBJECT_CLASS_VIOLATION].append(
            f"Directory {new_dir} must have all required attributes. Attributes ({empty}) is empty;"
        )

    return _errors, dropped_attributes, permitted_attributes
