"""Attribute Type management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Body, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.ldap_schema import ldap_schema_router
from ldap_protocol.ldap_schema.attribute_type_crud import (
    AttributeTypePaginationSchema,
    AttributeTypeSchema,
    AttributeTypeUpdateSchema,
    create_attribute_type,
    delete_attribute_types_by_names,
    get_attribute_type_by_name,
    get_attribute_types_paginator,
    modify_attribute_type,
)
from ldap_protocol.utils.pagination import PaginationParams

_DEFAULT_ATTRIBUTE_TYPE_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.15"
_DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD = False
_DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM = False


@ldap_schema_router.post(
    "/attribute_type",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_attribute_type(
    request_data: AttributeTypeSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Create a new attribute type.

    Args:
        request_data (AttributeTypeSchema): Data for creating attribute type.
        session (AsyncSession): Database session.
    """
    await create_attribute_type(
        oid=request_data.oid,
        name=request_data.name,
        syntax=_DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
        single_value=request_data.single_value,
        no_user_modification=_DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
        is_system=_DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM,
        session=session,
    )


@ldap_schema_router.get(
    "/attribute_type/{attribute_type_name}",
    response_model=AttributeTypeSchema,
    status_code=status.HTTP_200_OK,
)
async def get_one_attribute_type(
    attribute_type_name: str,
    session: FromDishka[AsyncSession],
) -> AttributeTypeSchema:
    """Retrieve a single attribute type by name.

    Args:
        attribute_type_name (str): Name of the attribute type.
        session (AsyncSession): Database session.

    Returns:
        AttributeTypeSchema: Attribute type schema.

    Raises:
        HTTPException: If attribute type not found.
    """
    attribute_type = await get_attribute_type_by_name(
        attribute_type_name,
        session,
    )

    if not attribute_type:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Attribute Type not found.",
        )

    return AttributeTypeSchema.from_db(attribute_type)


@ldap_schema_router.get(
    "/attribute_types/{page_number}",
    response_model=AttributeTypePaginationSchema,
    status_code=status.HTTP_200_OK,
)
async def get_list_attribute_types_with_pagination(
    page_number: int,
    session: FromDishka[AsyncSession],
    page_size: int = 50,
) -> AttributeTypePaginationSchema:
    """Retrieve a paginated list of attribute types.

    Args:
        page_number (int): Page number.
        session (FromDishka[AsyncSession]): Database session.
        page_size (int): Number of items per page (Default value = 50)

    Returns:
        AttributeTypePaginationSchema: Paginated attribute types.
    """
    params = PaginationParams(
        page_number=page_number,
        page_size=page_size,
    )
    pagination_result = await get_attribute_types_paginator(
        params=params,
        session=session,
    )

    items = [
        AttributeTypeSchema.from_db(item) for item in pagination_result.items
    ]
    return AttributeTypePaginationSchema(
        metadata=pagination_result.metadata,
        items=items,
    )


@ldap_schema_router.patch(
    "/attribute_type/{attribute_type_name}",
    status_code=status.HTTP_200_OK,
)
async def modify_one_attribute_type(
    attribute_type_name: str,
    request_data: AttributeTypeUpdateSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Modify an attribute type.

    Args:
        attribute_type_name (str): Name of the attribute type to modify.
        request_data (AttributeTypeUpdateSchema): Data to update.
        session (AsyncSession): Database session.

    Raises:
        HTTPException: If attribute type not found or is a system attribute.
    """
    attribute_type = await get_attribute_type_by_name(
        attribute_type_name,
        session,
    )
    if not attribute_type:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Attribute Type not found.",
        )

    if attribute_type.is_system:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "System attribute type cannot be modified.",
        )

    request_data.syntax = _DEFAULT_ATTRIBUTE_TYPE_SYNTAX
    request_data.no_user_modification = _DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD
    await modify_attribute_type(
        attribute_type=attribute_type,
        new_statement=request_data,
        session=session,
    )


@ldap_schema_router.post(
    "/attribute_types/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_attribute_types(
    attribute_types_names: Annotated[list[str], Body(embed=True)],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete attribute types by their names.

    Args:
        attribute_types_names (list[str]): List of attribute type names.
        session (AsyncSession): Database session.

    Raises:
        HTTPException: If no attribute type names are provided.
    """
    if not attribute_types_names:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Attribute Type names not found.",
        )

    await delete_attribute_types_by_names(attribute_types_names, session)
