"""Object Class management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Query, status
from pydantic import BaseModel

from api.ldap_schema import LimitedListType
from api.ldap_schema.adapters.object_class import ObjectClassFastAPIAdapter
from api.ldap_schema.attribute_type_router import ldap_schema_router
from api.ldap_schema.schema import (
    ObjectClassPaginationSchema,
    ObjectClassRequestSchema,
    ObjectClassSchema,
    ObjectClassUpdateSchema,
)
from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    PaginationParams,
)


@ldap_schema_router.post(
    "/object_class",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_object_class(
    request_data: ObjectClassRequestSchema,
    adapter: FromDishka[ObjectClassFastAPIAdapter],
) -> None:
    """Create a new Object Class.

    \f
    :param ObjectClassRequestSchema request_data:
        Data for creating Object Class.
    :param FromDishka[ObjectClassFastAPIAdapter] adapter:
        Object Class FastAPI Adapter.
    :raises HTTPException: 409 if object class already exists
    :return None.
    """
    await adapter.create(request_data=request_data)


@ldap_schema_router.get(
    "/object_class/{object_class_name}",
    response_model=ObjectClassSchema,
    status_code=status.HTTP_200_OK,
)
async def get_one_object_class(
    object_class_name: str,
    adapter: FromDishka[ObjectClassFastAPIAdapter],
) -> BaseModel:
    """Retrieve a one object class.

    \f
    :param str object_class_name: name of the Object Class.
    :param FromDishka[ObjectClassFastAPIAdapter] adapter:
        Object Class FastAPI Adapter.
    :return ObjectClassSchema: One Object Class Schemas.
    """
    return await adapter.get(object_class_name)


@ldap_schema_router.get(
    "/object_classes",
    response_model=ObjectClassPaginationSchema,
    status_code=status.HTTP_200_OK,
)
async def get_list_object_classes_with_pagination(
    adapter: FromDishka[ObjectClassFastAPIAdapter],
    params: Annotated[PaginationParams, Query()],
) -> BasePaginationSchema:
    """Retrieve a list of all object classes with paginate.

    \f
    :param FromDishka[ObjectClassFastAPIAdapter] adapter:
        Object Class FastAPI Adapter.
    :param PaginationParams params: Pagination parameters.
    :return ObjectClassPaginationSchema: Paginator.
    """
    return await adapter.get_list_paginated(params=params)


@ldap_schema_router.patch(
    "/object_class/{object_class_name}",
    status_code=status.HTTP_200_OK,
)
async def modify_one_object_class(
    object_class_name: str,
    request_data: ObjectClassUpdateSchema,
    adapter: FromDishka[ObjectClassFastAPIAdapter],
) -> None:
    """Modify an Object Class.

    \f
    :param str object_class_name: Name of the Object Class for modifying.
    :param ObjectClassUpdateSchema request_data: Changed data.
    :param FromDishka[ObjectClassFastAPIAdapter] adapter:
        Object Class FastAPI Adapter.
    :return None.
    """
    await adapter.update(object_class_name, request_data)


@ldap_schema_router.post(
    "/object_class/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_object_classes(
    object_classes_names: LimitedListType,
    adapter: FromDishka[ObjectClassFastAPIAdapter],
) -> None:
    """Delete Object Classes by their names.

    \f
    :param LimitedListType object_classes_names: List of Object Classes names.
    :param FromDishka[ObjectClassFastAPIAdapter] adapter:
        Object Class FastAPI Adapter.
    :return None: None
    """
    await adapter.delete_bulk(object_classes_names)
