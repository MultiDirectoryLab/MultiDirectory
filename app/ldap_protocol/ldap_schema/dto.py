"""ldap schema DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from enums import KindType


@dataclass
class AttributeTypeDTO:
    """Attribute Type DTO."""

    id: int | None
    oid: str
    name: str
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool

    def get_id(self) -> int:
        """Get the ID of the attribute type."""
        if not self.id:
            raise ValueError("ID is not set for the audit destination.")
        return self.id


@dataclass
class AttributeTypeUpdateDTO:
    """Attribute Type Update DTO."""

    syntax: str
    single_value: bool
    no_user_modification: bool


@dataclass
class ObjectClassRequestDTO:
    """Object Class Request DTO."""

    oid: str
    name: str
    superior_name: str | None
    kind: KindType
    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]
    is_system: bool


@dataclass
class ObjectClassDTO:
    """Object Class DTO."""

    id: int
    oid: str
    name: str
    superior_name: str | None
    kind: KindType
    is_system: bool
    attribute_types_must: list[AttributeTypeDTO]
    attribute_types_may: list[AttributeTypeDTO]


@dataclass
class ObjectClassUpdateDTO:
    """Object Class Update DTO."""

    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]


@dataclass
class EntityTypeDTO:
    """Entity Type DTO."""

    id: int | None
    name: str
    is_system: bool
    object_class_names: list[str]

    def get_id(self) -> int:
        """Get the ID of the entity type."""
        if not self.id:
            raise ValueError("ID is not set for the entity type.")
        return self.id


@dataclass
class EntityTypeUpdateDTO:
    """Entity Type Update DTO."""

    name: str
    object_class_names: list[str]
