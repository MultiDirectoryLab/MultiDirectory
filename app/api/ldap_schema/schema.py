"""ldap schema schema.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel, Field

from enums import KindType
from ldap_protocol.ldap_schema.constants import (
    DEFAULT_ENTITY_TYPE_IS_SYSTEM,
    OID_REGEX_PATTERN,
)
from ldap_protocol.utils.pagination import BasePaginationSchema


class AttributeTypeSchema(BaseModel):
    """Attribute Type Schema."""

    oid: str = Field(pattern=OID_REGEX_PATTERN)
    name: str = Field(min_length=1, max_length=255)
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool


class AttributeTypeUpdateSchema(BaseModel):
    """Attribute Type Schema for modify/update."""

    syntax: str
    single_value: bool
    no_user_modification: bool


class AttributeTypePaginationSchema(BasePaginationSchema[AttributeTypeSchema]):
    """Attribute Type Schema with pagination result."""

    items: list[AttributeTypeSchema]


class ObjectClassSchema(BaseModel):
    """Object Class Request Schema."""

    oid: str = Field(pattern=OID_REGEX_PATTERN)
    name: str = Field(min_length=1, max_length=255)
    superior_name: str | None
    kind: KindType
    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]
    is_system: bool = False


class ObjectClassPaginationSchema(BasePaginationSchema[ObjectClassSchema]):
    """Object Class Schema with pagination result."""

    items: list[ObjectClassSchema]


class ObjectClassUpdateSchema(BaseModel):
    """Object Class Schema for modify/update."""

    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]


class EntityTypeSchema(BaseModel):
    """Entity Type Schema."""

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
