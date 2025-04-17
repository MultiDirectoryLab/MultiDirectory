"""API for LDAP Schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import PartialAttribute
from ldap_protocol.ldap_schema.object_class_crud import (
    get_object_classes_by_names,
)
from models import Attribute, AttributeType, Directory, ObjectClass


async def get_flat_ldap_schema(
    session: AsyncSession,
) -> dict[str, tuple[list[AttributeType], list[AttributeType], int]]:
    """Return the LDAP schema.

    :return: The LDAP schema.
    """
    flat_schema: dict[str, tuple[list, list, int]] = dict()
    object_class_names: list[str] = []
    depth: int = 0

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

    while True:
        depth += 1
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

        if not object_classes:
            break

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

    :param session: The database session.
    :param object_class_names: The object class names.
    :raises ValueError: If the object class name is not found in the schema.
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


@dataclass
class ObjectClassValidationResult:
    """Result of validation Object Classes."""

    errors: dict[LDAPCodes, list[str]] = field(
        default_factory=lambda: defaultdict(list)
    )
    structural_object_class_names: list[str] = field(default_factory=list)


async def validate_object_class_by_ldap_schema(
    session: AsyncSession,
    directory: Directory,
    object_class_names: set[str],
) -> ObjectClassValidationResult:
    """Apply the LDAP schema to the directory Object Classes.

    :param session: The database session.
    :param directory: The directory.
    :param object_class_names: The object class names.
    :return: The validation result.
    """
    result = ObjectClassValidationResult()

    object_classes = await get_object_classes_by_names(
        object_class_names,
        session,
    )

    for object_class in object_classes:
        if object_class.is_structural:
            result.structural_object_class_names.append(object_class.name)

    if not result.structural_object_class_names:
        result.errors[LDAPCodes.OBJECT_CLASS_VIOLATION].append(
            f"Entry {directory} must have exactly one structural object class.\
            Object classes: {object_class_names}"
        )

    return result


@dataclass
class AttributesValidationResult:
    """Result of validation Attributes or Partial Attributes."""

    errors: dict[LDAPCodes, list[str]] = field(
        default_factory=lambda: defaultdict(list)
    )
    useless_attributes: list[Attribute | PartialAttribute] = field(
        default_factory=list
    )
    correct_attributes: list[Attribute | PartialAttribute] = field(
        default_factory=list
    )


async def validate_attributes_by_ldap_schema(
    session: AsyncSession,
    directory: Directory,
    attributes: list[Attribute] | list[PartialAttribute],
    object_class_names: set[str],
) -> AttributesValidationResult:
    """Apply the LDAP schema to the directory Attributes or Partial Attributes.

    :param session: The database session.
    :param directory: The directory.
    :param attributes: The attributes to validate.
    :param object_class_names: The object class names.
    :return: The validation result.
    """
    result = AttributesValidationResult()

    (
        must_names,
        may_names,
    ) = await get_attribute_type_names_by_object_class_names(
        session,
        object_class_names,
    )

    must_names_touched: set[str] = set()
    for attribute in attributes:
        if attribute.name in must_names:
            result.correct_attributes.append(attribute)
            must_names_touched.add(attribute.name)
            if not attribute.values:
                result.errors[LDAPCodes.INVALID_ATTRIBUTE_SYNTAX].append(
                    f"Attribute {attribute} don`t have a value;"
                )
        elif attribute.name in may_names:
            result.correct_attributes.append(attribute)
        else:
            result.useless_attributes.append(attribute)

    if names := must_names - must_names_touched:
        result.errors[LDAPCodes.OBJECT_CLASS_VIOLATION].append(
            f"Directory {directory} must have all required (MUST) attributes.\
            Attributes ({names}) missing;"
        )

    return result
