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
from models import Attribute, AttributeType, ObjectClass

type ObjectClassNameLowerCaseType = str


class FlatObjectClass:
    """Flat Object Class."""

    oid: str
    name: str

    @property
    def name_lower(self) -> ObjectClassNameLowerCaseType:
        """Return the name in lower case."""
        return self.name.lower()

    superior_name: str | None

    @property
    def superior_name_lower(self) -> ObjectClassNameLowerCaseType | None:
        """Return the superior name in lower case."""
        if self.superior_name:
            return self.superior_name.lower()
        return None

    @property
    def superior(self) -> None:
        raise NotImplementedError("superior dont touchable")

    kind: Literal["AUXILIARY", "STRUCTURAL", "ABSTRACT"]
    is_system: bool
    attribute_types_must: list[AttributeType]
    attribute_types_may: list[AttributeType]

    @property
    def attribute_type_names_must(self) -> set[str]:
        """Display attribute types must."""
        return {attr.name for attr in self.attribute_types_must}

    @property
    def attribute_type_names_may(self) -> set[str]:
        """Display attribute types may."""
        return {attr.name for attr in self.attribute_types_may}

    def __str__(self) -> str:
        """FlatObjectClass name."""
        return f"FlatObjectClass({self.name})"

    def __repr__(self) -> str:
        """FlatObjectClass oid and name."""
        return f"FlatObjectClass({self.oid}:{self.name})"

    def __init__(  # noqa: D107
        self,
        object_class: ObjectClass,
    ) -> None:
        self.oid = object_class.oid
        self.name = object_class.name
        self.superior_name = object_class.superior_name
        self.kind = object_class.kind
        self.is_structural = object_class.is_structural
        self.is_system = object_class.is_system
        self.attribute_types_must = object_class.attribute_types_must[:]
        self.attribute_types_may = object_class.attribute_types_may[:]


async def get_flat_ldap_schema(
    session: AsyncSession,
) -> dict[ObjectClassNameLowerCaseType, FlatObjectClass]:
    """Return the LDAP schema.

    :return: The LDAP schema.
    """
    flat_schema: dict[ObjectClassNameLowerCaseType, FlatObjectClass] = dict()

    type ObjectClassNameCamelCaseType = str
    object_class_names: list[ObjectClassNameCamelCaseType] = []

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
        flat_object_class = FlatObjectClass(object_class)
        flat_schema[flat_object_class.name_lower] = flat_object_class
        object_class_names.append(flat_object_class.name)

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

        for object_class in object_classes:
            flat_object_class = FlatObjectClass(object_class)

            if flat_object_class.superior_name_lower:
                parent_flat_object_class = flat_schema[
                    flat_object_class.superior_name_lower
                ]
                flat_object_class.attribute_types_must.extend(
                    parent_flat_object_class.attribute_types_must
                )
                flat_object_class.attribute_types_may.extend(
                    parent_flat_object_class.attribute_types_may
                )

            flat_schema[flat_object_class.name_lower] = flat_object_class
            object_class_names.append(flat_object_class.name)

    return flat_schema


async def _get_flat_attribute_type_names_by_object_class_names(
    object_class_names: list[str] | set[str],
    flat_ldap_schema: dict[ObjectClassNameLowerCaseType, FlatObjectClass],
) -> tuple[set[str], set[str]]:
    """Return the attribute types by object class name.

    :param session: The database session.
    :param object_class_names: The object class names.
    :raises ValueError: If the object class name is not found in the schema.
    :return: The attribute types by object class name.
    """
    flat_object_classes: list[FlatObjectClass] = []
    for object_class_name in object_class_names:
        flat_object_class = flat_ldap_schema.get(object_class_name.lower())
        if flat_object_class is None:
            raise ValueError(
                f"Object class {object_class_name} not found in schema."
            )
        else:
            flat_object_classes.append(flat_object_class)

    attribute_type_names_must: set[str] = set()
    attribute_type_names_may: set[str] = set()

    for flat_object_class in flat_object_classes:
        attribute_type_names_must.update(
            flat_object_class.attribute_type_names_must
        )
        attribute_type_names_may.update(
            flat_object_class.attribute_type_names_may
        )

    attribute_type_names_may -= attribute_type_names_must
    return (
        {n.lower() for n in attribute_type_names_must},
        {n.lower() for n in attribute_type_names_may},
    )


type ObjectClassValidationResultAlertsType = dict[
    Literal[LDAPCodes.OBJECT_CLASS_VIOLATION],
    list[str],
]


@dataclass
class ObjectClassValidationResult:
    """Result of validation Object Classes."""

    alerts: ObjectClassValidationResultAlertsType = field(
        default_factory=lambda: defaultdict(list)
    )


async def validate_chunck_object_classes_by_ldap_schema(
    object_class_names: set[str],
    flat_ldap_schema: dict[ObjectClassNameLowerCaseType, FlatObjectClass],
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

    flat_object_classes: list[FlatObjectClass] = []
    for object_class_name in object_class_names:
        flat_object_class = flat_ldap_schema.get(object_class_name.lower())
        if flat_object_class is None:
            result.alerts[LDAPCodes.OBJECT_CLASS_VIOLATION].append(
                f"Object class {object_class_name} not found in schema."
            )
        else:
            flat_object_classes.append(flat_object_class)

    if len(flat_object_classes) != len(object_class_names):
        result.alerts[LDAPCodes.OBJECT_CLASS_VIOLATION].append(
            f"Object classes not all found in schema: {object_class_names}.\
            Found: {flat_object_classes}"
        )

    for flat_object_class in flat_object_classes:
        if flat_object_class.is_structural:
            break
    else:
        result.alerts[LDAPCodes.OBJECT_CLASS_VIOLATION].append(
            f"Entry must have one structural object class.\
            Object classes: {object_class_names}"
        )

    return result


type AttributesValidationResultAlertsType = dict[
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

    alerts: AttributesValidationResultAlertsType = field(
        default_factory=lambda: defaultdict(list)
    )
    attributes_rejected: list[Attribute | PartialAttribute] = field(
        default_factory=list
    )
    attributes_accepted: list[Attribute | PartialAttribute] = field(
        default_factory=list
    )


async def validate_attributes_by_ldap_schema(
    attributes: list[Attribute] | list[PartialAttribute],
    object_class_names: set[str],
    flat_ldap_schema: dict[ObjectClassNameLowerCaseType, FlatObjectClass],
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
    ) = await _get_flat_attribute_type_names_by_object_class_names(
        object_class_names,
        flat_ldap_schema,
    )

    for attribute in attributes:
        if not attribute.values:
            result.alerts[LDAPCodes.INVALID_ATTRIBUTE_SYNTAX].append(
                attribute.name
            )

        if (
            attribute.name.lower() in must_names
            or attribute.name.lower() in may_names
        ):
            result.attributes_accepted.append(attribute)

        else:
            result.attributes_rejected.append(attribute)

    empty = [
        name.lower()
        for name in must_names
        if name
        not in {attr.name.lower() for attr in result.attributes_accepted}
    ]
    if empty:
        result.alerts[LDAPCodes.INVALID_ATTRIBUTE_SYNTAX].extend(empty)

    return result
