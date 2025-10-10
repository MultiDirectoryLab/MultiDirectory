"""Object Class management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Query, status

from api.ldap_schema import LimitedListType
from api.ldap_schema.adapters.object_class import ObjectClassFastAPIAdapter
from api.ldap_schema.attribute_type_router import ldap_schema_router
from api.ldap_schema.schema import (
    ObjectClassPaginationSchema,
    ObjectClassSchema,
    ObjectClassUpdateSchema,
)
from ldap_protocol.utils.pagination import PaginationParams


@ldap_schema_router.post("/object_class", status_code=status.HTTP_201_CREATED)
async def create_one_object_class(
    request_data: ObjectClassSchema[None],
    adapter: FromDishka[ObjectClassFastAPIAdapter],
) -> None:
    """Create a new Object Class."""
    await adapter.create(request_data)


@ldap_schema_router.get("/object_class/{object_class_name}")
async def get_one_object_class(
    object_class_name: str,
    adapter: FromDishka[ObjectClassFastAPIAdapter],
) -> ObjectClassSchema[int]:
    """Retrieve a one Object Class."""
    return await adapter.get(object_class_name)


@ldap_schema_router.get("/object_classes")
async def get_list_object_classes_with_pagination(
    adapter: FromDishka[ObjectClassFastAPIAdapter],
    params: Annotated[PaginationParams, Query()],
) -> ObjectClassPaginationSchema:
    """Retrieve a list of all object classes with paginate."""
    return await adapter.get_list_paginated(params=params)


@ldap_schema_router.patch("/object_class/{object_class_name}")
async def modify_one_object_class(
    object_class_name: str,
    request_data: ObjectClassUpdateSchema,
    adapter: FromDishka[ObjectClassFastAPIAdapter],
) -> None:
    """Modify an Object Class."""
    await adapter.update(object_class_name, request_data)


@ldap_schema_router.post("/object_class/delete")
async def delete_bulk_object_classes(
    object_classes_names: LimitedListType,
    adapter: FromDishka[ObjectClassFastAPIAdapter],
) -> None:
    """Delete Object Classes by their names."""
    await adapter.delete_bulk(object_classes_names)
