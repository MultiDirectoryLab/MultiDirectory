"""API for LDAP Schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_responses import PartialAttribute
from ldap_protocol.ldap_schema.object_class_crud import (
    get_object_classes_by_names,
)
from models import Attribute, AttributeType, ObjectClass


async def get_flat_ldap_schema(
    session: AsyncSession,
) -> dict[str, tuple[list[AttributeType], list[AttributeType]]]:
    """Return the LDAP schema.

    :return: The LDAP schema.
    """
    flat_schema: dict[str, tuple[list, list]] = dict()
    object_class_names: list[str] = []

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
        )
        object_class_names.append(object_class.name)

    while True:
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

    flat_object_classes: list[tuple[list, list]] = []
    for object_class_name in object_class_names:
        flat_object_class = flat_ldap_schema.get(object_class_name)
        if flat_object_class is None:
            raise ValueError(
                f"Object class {object_class_name} not found in schema."
            )
        else:
            flat_object_classes.append(flat_object_class)

    attribute_type_names_must: set[str] = set()
    attribute_type_names_may: set[str] = set()

    for attribute_types_must, attribute_types_may in flat_object_classes:
        attribute_type_names_must.update(
            {attribute_type.name for attribute_type in attribute_types_must}
        )
        attribute_type_names_may.update(
            {attribute_type.name for attribute_type in attribute_types_may}
        )

    attribute_type_names_may -= attribute_type_names_must
    return (attribute_type_names_must, attribute_type_names_may)


type ObjectClassValidationResultAlerts = dict[
    Literal[LDAPCodes.OBJECT_CLASS_VIOLATION],
    list[str],
]


@dataclass
class ObjectClassValidationResult:
    """Result of validation Object Classes."""

    alerts: ObjectClassValidationResultAlerts = field(
        default_factory=lambda: defaultdict(list)
    )


async def validate_chunck_object_classes_by_ldap_schema(
    session: AsyncSession,
    object_class_names: set[str],
) -> ObjectClassValidationResult:
    """Apply the LDAP schema to the directory Object Classes.

    :param session: The database session.
    :param object_class_names: The object class names.
    :return: The validation result.
    """
    result = ObjectClassValidationResult()

    if not object_class_names:
        result.alerts[LDAPCodes.OBJECT_CLASS_VIOLATION].append(
            "Object class names is empty."
        )

    if result.alerts:
        return result

    object_classes = await get_object_classes_by_names(
        object_class_names,
        session,
    )

    for object_class in object_classes:
        if object_class.is_structural:
            break
    else:
        result.alerts[LDAPCodes.OBJECT_CLASS_VIOLATION].append(
            f"Entry must have one structural object class.\
            Object classes: {object_class_names}"
        )

    return result


type AttributesValidationResultAlerts = dict[
    Literal[
        LDAPCodes.NO_SUCH_ATTRIBUTE,
        LDAPCodes.NO_SUCH_OBJECT,
        LDAPCodes.INVALID_ATTRIBUTE_SYNTAX,
        LDAPCodes.OBJECT_CLASS_VIOLATION,
    ],
    list[str],
]


@dataclass
class AttributesValidationResult:
    """Result of validation Attributes or Partial Attributes."""

    alerts: AttributesValidationResultAlerts = field(
        default_factory=lambda: defaultdict(list)
    )
    attributes_rejected: list[Attribute | PartialAttribute] = field(
        default_factory=list
    )
    attributes_accepted: list[Attribute | PartialAttribute] = field(
        default_factory=list
    )


async def validate_attributes_by_ldap_schema(
    session: AsyncSession,
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

    if not attributes:
        result.alerts[LDAPCodes.NO_SUCH_ATTRIBUTE].append(
            "Attributes is empty."
        )

    if not object_class_names:
        result.alerts[LDAPCodes.OBJECT_CLASS_VIOLATION].append(
            "Object class names is empty."
        )

    if result.alerts:
        return result

    (
        must_names,
        may_names,
    ) = await get_attribute_type_names_by_object_class_names(
        session,
        object_class_names,
    )

    for attribute in attributes:
        if not attribute.values:
            result.alerts[LDAPCodes.INVALID_ATTRIBUTE_SYNTAX].append(
                attribute.name
            )

        if attribute.name in must_names or attribute.name in may_names:
            result.attributes_accepted.append(attribute)

        else:
            result.attributes_rejected.append(attribute)

    empty = [
        name
        for name in must_names
        if name not in {attr.name for attr in result.attributes_accepted}
    ]
    if empty:
        result.alerts[LDAPCodes.INVALID_ATTRIBUTE_SYNTAX].extend(empty)

    return result
