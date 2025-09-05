"""ldap schema schema.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel

from enums import KindType
from ldap_protocol.utils.pagination import BasePaginationSchema


class AttributeTypeSchema(BaseModel):
    """Attribute Type Schema."""

    id: int
    oid: str
    name: str
    syntax: str
    single_value: bool
    no_user_modification: bool
    is_system: bool


class AttributeTypeRequestSchema(BaseModel):
    """Attribute Type Request Schema."""

    oid: str
    name: str
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
    """Object Class Schema."""

    oid: str
    name: str
    superior_name: str | None
    kind: KindType
    is_system: bool
    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]


class ObjectClassRequestSchema(BaseModel):
    """Object Class Request Schema."""

    oid: str
    name: str
    superior_name: str | None
    kind: KindType
    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]


class ObjectClassPaginationSchema(BasePaginationSchema[ObjectClassSchema]):
    """Object Class Schema with pagination result."""

    items: list[ObjectClassSchema]


class ObjectClassUpdateSchema(BaseModel):
    """Object Class Schema for modify/update."""

    attribute_type_names_must: list[str]
    attribute_type_names_may: list[str]
