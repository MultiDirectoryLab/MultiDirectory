"""ldap schema DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from typing import Generic, TypeVar

from enums import KindType


@dataclass
class AttributeTypeDTO:
    """Attribute Type DTO."""

    oid: str
    name: str
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool
    id: int | None = None

    def get_id(self) -> int:
        """Get the ID of the attribute type."""
        if not self.id:
            raise ValueError("ID is not set for the attribute type.")
        return self.id


_T = TypeVar("_T", AttributeTypeDTO, str)


@dataclass
class ObjectClassDTO(Generic[_T]):
    """Object Class DTO."""

    id: int | None
    oid: str
    name: str
    superior_name: str | None
    kind: KindType
    is_system: bool
    attribute_types_must: list[_T]
    attribute_types_may: list[_T]

    def get_id(self) -> int:
        """Get the ID of the object class."""
        if not self.id:
            raise ValueError("ID is not set for the object class.")
        return self.id


@dataclass
class EntityTypeDTO:
    """Entity Type DTO."""

    name: str
    is_system: bool
    object_class_names: list[str]
    id: int | None = None

    def get_id(self) -> int:
        """Get the ID of the entity type."""
        if not self.id:
            raise ValueError("ID is not set for the entity type.")
        return self.id
