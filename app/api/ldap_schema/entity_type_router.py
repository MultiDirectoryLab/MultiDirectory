"""Entity Type management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Query, status

from api.ldap_schema import LimitedListType, error_map
from api.ldap_schema.adapters.entity_type import LDAPEntityTypeFastAPIAdapter
from api.ldap_schema.object_class_router import ldap_schema_router
from api.ldap_schema.schema import (
    EntityTypePaginationSchema,
    EntityTypeSchema,
    EntityTypeUpdateSchema,
)
from ldap_protocol.utils.pagination import PaginationParams


@ldap_schema_router.post(
    "/entity_type",
    status_code=status.HTTP_201_CREATED,
    error_map=error_map,
)
async def create_one_entity_type(
    request_data: EntityTypeSchema[None],
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
) -> None:
    """Create a new Entity Type."""
    await adapter.create(request_data)


@ldap_schema_router.get("/entity_type/{entity_type_name}", error_map=error_map)
async def get_one_entity_type(
    entity_type_name: str,
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
) -> EntityTypeSchema[int]:
    """Retrieve a one Entity Type."""
    return await adapter.get(entity_type_name)


@ldap_schema_router.get("/entity_types", error_map=error_map)
async def get_list_entity_types_with_pagination(
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
    params: Annotated[PaginationParams, Query()],
) -> EntityTypePaginationSchema:
    """Retrieve a chunk of Entity Types with pagination."""
    return await adapter.get_list_paginated(params=params)


@ldap_schema_router.get(
    "/entity_type/{entity_type_name}/attrs",
    error_map=error_map,
)
async def get_entity_type_attributes(
    entity_type_name: str,
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
) -> list[str]:
    """Get all attribute names for an Entity Type."""
    return await adapter.get_entity_type_attributes(entity_type_name)


@ldap_schema_router.patch(
    "/entity_type/{entity_type_name}",
    error_map=error_map,
)
async def modify_one_entity_type(
    entity_type_name: str,
    request_data: EntityTypeUpdateSchema,
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
) -> None:
    """Modify an Entity Type."""
    await adapter.update(name=entity_type_name, data=request_data)


@ldap_schema_router.post("/entity_type/delete", error_map=error_map)
async def delete_bulk_entity_types(
    entity_type_names: LimitedListType,
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
) -> None:
    """Delete Entity Types by their names."""
    await adapter.delete_bulk(entity_type_names)
