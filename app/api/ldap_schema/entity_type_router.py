"""Entity Type management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Query, status
from pydantic import BaseModel

from api.ldap_schema import LimitedListType
from api.ldap_schema.adapters.entity_type import LDAPEntityTypeFastAPIAdapter
from api.ldap_schema.object_class_router import ldap_schema_router
from api.ldap_schema.schema import (
    EntityTypePaginationSchema,
    EntityTypeSchema,
    EntityTypeUpdateSchema,
)
from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    PaginationParams,
)


@ldap_schema_router.post(
    "/entity_type",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_entity_type(
    request_data: EntityTypeSchema,
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
) -> None:
    """Create a new Entity Type.

    \f
    :param EntityTypeSchema request_data: Data for creating Entity Type.
    :param FromDishka[LDAPEntityTypeFastAPIAdapter] adapter:
        LDAPEntityTypeFastAPIAdapter
    instance.
    :return None.
    """
    await adapter.create(
        request_data=request_data,
    )


@ldap_schema_router.get(
    "/entity_type/{entity_type_name}",
    response_model=EntityTypeSchema,
)
async def get_one_entity_type(
    entity_type_name: str,
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
) -> BaseModel:
    """Retrieve a one Entity Type.

    \f
    :param str entity_type_name: name of the Entity Type.
    :param FromDishka[LDAPEntityTypeFastAPIAdapter] adapter:
        LDAPEntityTypeFastAPIAdapter
    instance.
    :return EntityTypeSchema: Entity Type Schema.
    """
    return await adapter.get(entity_type_name)


@ldap_schema_router.get(
    "/entity_types",
    response_model=EntityTypePaginationSchema,
)
async def get_list_entity_types_with_pagination(
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
    params: Annotated[PaginationParams, Query()],
) -> BasePaginationSchema:
    """Retrieve a chunk of Entity Types with pagination.

    \f
    :param FromDishka[LDAPEntityTypeFastAPIAdapter] adapter:
        LDAPEntityTypeFastAPIAdapter
    instance.
    :param PaginationParams params: Pagination parameters.
    :return EntityTypePaginationSchema: Paginator Schema.
    """
    return await adapter.get_list_paginated(params=params)


@ldap_schema_router.get("/entity_type/{entity_type_name}/attrs")
async def get_entity_type_attributes(
    entity_type_name: str,
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
) -> list[str]:
    """Get all attribute names for an Entity Type.

    \f
    :param str entity_type_name: Name of the Entity Type.
    :param FromDishka[LDAPEntityTypeFastAPIAdapter] adapter:
        LDAPEntityTypeFastAPIAdapter
    instance.
    :return list[str]: List of attribute names.
    """
    return await adapter.get_entity_type_attributes(entity_type_name)


@ldap_schema_router.patch("/entity_type/{entity_type_name}")
async def modify_one_entity_type(
    entity_type_name: str,
    request_data: EntityTypeUpdateSchema,
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
) -> None:
    """Modify an Entity Type.

    \f
    :param str entity_type_name: Name of the Entity Type for modifying.
    :param EntityTypeUpdateSchema request_data: Changed data.
    :param FromDishka[LDAPEntityTypeFastAPIAdapter] adapter:
        LDAPEntityTypeFastAPIAdapter
    instance.
    :return None.
    """
    await adapter.update(
        name=entity_type_name,
        request_data=request_data,
    )


@ldap_schema_router.post("/entity_type/delete")
async def delete_bulk_entity_types(
    entity_type_names: LimitedListType,
    adapter: FromDishka[LDAPEntityTypeFastAPIAdapter],
) -> None:
    """Delete Entity Types by their names.

    \f
    :param LimitedListType entity_type_names: List of Entity Type names.
    :param FromDishka[LDAPEntityTypeFastAPIAdapter] adapter:
        LDAPEntityTypeFastAPIAdapter
    instance.
    :return None: None
    """
    await adapter.delete_bulk(entity_type_names)
