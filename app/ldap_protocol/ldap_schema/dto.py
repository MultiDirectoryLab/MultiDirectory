"""ldap schema DTO.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import dataclass

from enums import KindType


@dataclass
class AttributeTypeDTO:
    """Attribute Type DTO."""

    id: int
    oid: str
    name: str
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool


@dataclass
class AttributeTypeUpdateDTO:
    """Attribute Type Update DTO."""

    syntax: str
    single_value: bool
    no_user_modification: bool


@dataclass
class ObjectClassDTO:
    """Object Class DTO."""

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
