"""ldap schema schema.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import field
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

from enums import KindType
from ldap_protocol.ldap_schema.constants import (
    DEFAULT_ENTITY_TYPE_IS_SYSTEM,
    OID_REGEX_PATTERN,
)
from ldap_protocol.utils.pagination import BasePaginationSchema

_IdT = TypeVar("_IdT", int, None)


class AttributeTypeSchema(BaseModel, Generic[_IdT]):  # noqa: UP046
    """Attribute Type Schema."""

    id: _IdT = Field(default=None)  # type: ignore[assignment]
    oid: str = Field(pattern=OID_REGEX_PATTERN, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool


class AttributeTypeExtendedSchema(BaseModel):
    """Attribute Type Extended Schema request."""

    id: int
    oid: str = Field(pattern=OID_REGEX_PATTERN, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool
    object_class_names: set[str] = field(default_factory=set)


class AttributeTypeUpdateSchema(BaseModel):
    """Attribute Type Schema for modify/update."""

    syntax: str
    single_value: bool
    no_user_modification: bool


class AttributeTypePaginationSchema(BasePaginationSchema[AttributeTypeSchema]):
    """Attribute Type Schema with pagination result."""

    items: list[AttributeTypeSchema]


class ObjectClassSchema(BaseModel, Generic[_IdT]):  # noqa: UP046
    """Object Class Request Schema."""

    id: _IdT = Field(default=None)  # type: ignore[assignment]
    oid: str = Field(pattern=OID_REGEX_PATTERN, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    superior_name: str | None
    kind: KindType
    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]
    is_system: bool = False


class ObjectClassExtendedSchema(BaseModel):
    """Object Class Extended Schema request."""

    id: int
    oid: str = Field(pattern=OID_REGEX_PATTERN, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    superior_name: str | None
    kind: KindType
    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]
    is_system: bool = False
    entity_type_names: set[str] = field(default_factory=set)


class ObjectClassPaginationSchema(BasePaginationSchema[ObjectClassSchema]):
    """Object Class Schema with pagination result."""

    items: list[ObjectClassSchema]


class ObjectClassUpdateSchema(BaseModel):
    """Object Class Schema for modify/update."""

    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]


class EntityTypeSchema(BaseModel, Generic[_IdT]):  # noqa: UP046
    """Entity Type Schema."""

    id: _IdT = Field(default=None)  # type: ignore[assignment]
    name: str
    is_system: bool
    object_class_names: list[str] = Field(
        default_factory=list,
        min_length=1,
        max_length=10000,
    )


class EntityTypeUpdateSchema(BaseModel):
    """Entity Type Schema for modify/update."""

    is_system: bool = DEFAULT_ENTITY_TYPE_IS_SYSTEM
    name: str
    object_class_names: list[str] = Field(
        default_factory=list,
        min_length=1,
        max_length=10000,
    )


class EntityTypePaginationSchema(BasePaginationSchema[EntityTypeSchema]):
    """Entity Type Schema with pagination result."""

    items: list[EntityTypeSchema]
