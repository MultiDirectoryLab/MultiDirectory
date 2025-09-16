"""ldap schema DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass
from typing import Generic, TypeVar

from enums import KindType

_IdT = TypeVar("_IdT", int, None)


@dataclass
class AttributeTypeDTO(Generic[_IdT]):
    """Attribute Type DTO."""

    oid: str
    name: str
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool
    id: _IdT = None  # type: ignore


_LinkT = TypeVar("_LinkT", AttributeTypeDTO, str)


@dataclass
class ObjectClassDTO(Generic[_IdT, _LinkT]):
    """Object Class DTO."""

    id: _IdT
    oid: str
    name: str
    superior_name: str | None
    kind: KindType
    is_system: bool
    attribute_types_must: list[_LinkT]
    attribute_types_may: list[_LinkT]


@dataclass
class EntityTypeDTO(Generic[_IdT]):
    """Entity Type DTO."""

    name: str
    is_system: bool
    object_class_names: list[str]
    id: _IdT = None  # type: ignore
