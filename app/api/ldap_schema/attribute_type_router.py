"""Attribute Type management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Query, status

from api.ldap_schema import LimitedListType, ldap_schema_router
from api.ldap_schema.adapters.attribute_type import AttributeTypeFastAPIAdapter
from api.ldap_schema.schema import (
    AttributeTypePaginationSchema,
    AttributeTypeSchema,
    AttributeTypeUpdateSchema,
)
from ldap_protocol.utils.pagination import PaginationParams


@ldap_schema_router.post(
    "/attribute_type",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_attribute_type(
    request_data: AttributeTypeSchema[None],
    adapter: FromDishka[AttributeTypeFastAPIAdapter],
) -> None:
    """Create a new Attribute Type."""
    await adapter.create(request_data)


@ldap_schema_router.get("/attribute_type/{attribute_type_name}")
async def get_one_attribute_type(
    attribute_type_name: str,
    adapter: FromDishka[AttributeTypeFastAPIAdapter],
) -> AttributeTypeSchema:
    """Retrieve a one Attribute Type."""
    return await adapter.get(attribute_type_name)


@ldap_schema_router.get("/attribute_types")
async def get_list_attribute_types_with_pagination(
    adapter: FromDishka[AttributeTypeFastAPIAdapter],
    params: Annotated[PaginationParams, Query()],
) -> AttributeTypePaginationSchema:
    """Retrieve a chunk of Attribute Types with pagination."""
    return await adapter.get_list_paginated(params)


@ldap_schema_router.patch("/attribute_type/{attribute_type_name}")
async def modify_one_attribute_type(
    attribute_type_name: str,
    request_data: AttributeTypeUpdateSchema,
    adapter: FromDishka[AttributeTypeFastAPIAdapter],
) -> None:
    """Modify an Attribute Type."""
    await adapter.update(name=attribute_type_name, data=request_data)


@ldap_schema_router.post("/attribute_types/delete")
async def delete_bulk_attribute_types(
    attribute_types_names: LimitedListType,
    adapter: FromDishka[AttributeTypeFastAPIAdapter],
) -> None:
    """Delete Attribute Types by their names."""
    await adapter.delete_bulk(attribute_types_names)
