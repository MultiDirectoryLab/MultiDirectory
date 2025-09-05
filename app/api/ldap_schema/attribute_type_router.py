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
    AttributeTypeRequestSchema,
    AttributeTypeSchema,
    AttributeTypeUpdateSchema,
)
from ldap_protocol.utils.pagination import PaginationParams


@ldap_schema_router.post(
    "/attribute_type",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_attribute_type(
    request_data: AttributeTypeRequestSchema,
    adapter: FromDishka[AttributeTypeFastAPIAdapter],
) -> None:
    """Create a new Attribute Type.

    \f
    :param AttributeTypeRequestSchema request_data:
        Data for creating Attribute Type.
    :param FromDishka[AttributeTypeFastAPIAdapter] adapter: Attribute Type\
          manager.
    :raises HTTPException: 409 if attr already exists
    :return None.
    """
    await adapter.create_one_attribute_type(request_data)


@ldap_schema_router.get(
    "/attribute_type/{attribute_type_name}",
    response_model=AttributeTypeSchema,
    status_code=status.HTTP_200_OK,
)
async def get_one_attribute_type(
    attribute_type_name: str,
    adapter: FromDishka[AttributeTypeFastAPIAdapter],
) -> AttributeTypeSchema:
    """Retrieve a one Attribute Type.

    \f
    :param str attribute_type_name: name of the Attribute Type.
    :param FromDishka[AttributeTypeFastAPIAdapter] adapter:
        Attribute Type adapter.
    :return AttributeTypeSchema: Attribute Type Schema.
    """
    return await adapter.get_one_attribute_type(attribute_type_name)


@ldap_schema_router.get(
    "/attribute_types",
    response_model=AttributeTypePaginationSchema,
    status_code=status.HTTP_200_OK,
)
async def get_list_attribute_types_with_pagination(
    adapter: FromDishka[AttributeTypeFastAPIAdapter],
    params: Annotated[PaginationParams, Query()],
) -> AttributeTypePaginationSchema:
    """Retrieve a chunk of Attribute Types with pagination.

    \f
    :param FromDishka[AttributeTypeFastAPIAdapter] adapter:
         Attribute Type adapter.
    :param PaginationParams params: Pagination parameters.
    :return AttributeTypePaginationSchema: Paginator Schema.
    """
    return await adapter.get_list_attribute_types_with_pagination(
        params=params,
    )


@ldap_schema_router.patch(
    "/attribute_type/{attribute_type_name}",
    status_code=status.HTTP_200_OK,
)
async def modify_one_attribute_type(
    attribute_type_name: str,
    request_data: AttributeTypeUpdateSchema,
    adapter: FromDishka[AttributeTypeFastAPIAdapter],
) -> None:
    """Modify an Attribute Type.

    \f
    :param str attribute_type_name: name of the Attribute Type for modifying.
    :param AttributeTypeUpdateSchema request_data: Changed data.
    :param FromDishka[AttributeTypeFastAPIAdapter] adapter:
        Attribute Type adapter.
    :raises HTTPException: 403 if attr read-only
    :return None.
    """
    await adapter.modify_one_attribute_type(
        attribute_type_name=attribute_type_name,
        request_data=request_data,
    )


@ldap_schema_router.post(
    "/attribute_types/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_attribute_types(
    attribute_types_names: LimitedListType,
    adapter: FromDishka[AttributeTypeFastAPIAdapter],
) -> None:
    """Delete Attribute Types by their names.

    \f
    :param LimitedListType attribute_types_names: List of Attribute Type names
    :param FromDishka[AttributeTypeFastAPIAdapter] adapter:
        Attribute Type adapter.
    :return None: None
    """
    await adapter.delete_bulk_attribute_types(
        attribute_types_names=attribute_types_names,
    )
