"""Attribute Type management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka.integrations.fastapi import FromDishka
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.ldap_schema import LimitedListType, ldap_schema_router
from ldap_protocol.ldap_schema.attribute_type_crud import (
    AttributeTypeDAO,
    AttributeTypePaginationSchema,
    AttributeTypeSchema,
    AttributeTypeUpdateSchema,
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
    attribute_type_dao: FromDishka[AttributeTypeDAO],
) -> None:
    """Create a new attribute type.

    \f
    :param AttributeTypeSchema request_data: Data for creating attribute type.
    :param FromDishka[AttributeTypeDAO] attribute_type_dao: Attribute Type\
          manager.
    :param FromDishka[AsyncSession] session: Database session.
    :return None.
    """
    await attribute_type_dao.create_one(
        oid=request_data.oid,
        name=request_data.name,
        syntax=_DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
        single_value=request_data.single_value,
        no_user_modification=_DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
        is_system=_DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM,
    )
    await session.commit()


@ldap_schema_router.get(
    "/attribute_type/{attribute_type_name}",
    response_model=AttributeTypeSchema,
    status_code=status.HTTP_200_OK,
)
async def get_one_attribute_type(
    attribute_type_name: str,
    attribute_type_dao: FromDishka[AttributeTypeDAO],
) -> AttributeTypeSchema:
    """Retrieve a one attribute types.

    \f
    :param str attribute_type_name: name of the Attribute Type.
    :param FromDishka[AttributeTypeDAO] attribute_type_dao: Attribute Type\
        manager.
    :raise HTTP_404_NOT_FOUND: If Attribute Type not found.
    :return AttributeTypeSchema: One Attribute Type Schemas.
    """
    attribute_type = await attribute_type_dao.get_one_by_name(
        attribute_type_name,
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
    attribute_type_dao: FromDishka[AttributeTypeDAO],
    page_size: int = 50,
) -> AttributeTypePaginationSchema:
    """Retrieve a list of all attribute types with paginate.

    \f
    :param int page_number: number of page.
    :param FromDishka[AttributeTypeDAO] attribute_type_dao: Attribute Type\
        manager.
    :param int page_size: number of items per page.
    :return AttributeTypePaginationSchema: Paginator.
    """
    params = PaginationParams(
        page_number=page_number,
        page_size=page_size,
    )

    pagination_result = await attribute_type_dao.get_paginator(params=params)

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
    attribute_type_dao: FromDishka[AttributeTypeDAO],
) -> None:
    """Modify an Attribute Type.

    \f
    :param str attribute_type_name: name of the attribute type for modifying.
    :param AttributeTypeUpdateSchema request_data: Changed data.
    :param FromDishka[AsyncSession] session: Database session.
    :param FromDishka[AttributeTypeDAO] attribute_type_dao: Attribute Type\
        manager.
    :raise HTTP_404_NOT_FOUND: If attribute type not found.
    :raise HTTP_400_BAD_REQUEST: If attribute type is system->cannot be changed
    :return None.
    """
    attribute_type = await attribute_type_dao.get_one_by_name(
        attribute_type_name
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
    await attribute_type_dao.modify_one(
        attribute_type=attribute_type,
        new_statement=request_data,
    )
    await session.commit()


@ldap_schema_router.post(
    "/attribute_types/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_attribute_types(
    attribute_types_names: LimitedListType,
    session: FromDishka[AsyncSession],
    attribute_type_dao: FromDishka[AttributeTypeDAO],
) -> None:
    """Delete attribute types by their names.

    \f
    :param LimitedListType attribute_types_names: List of attribute types names
    :param FromDishka[AsyncSession] session: Database session.
    :param FromDishka[AttributeTypeDAO] attribute_type_dao: Attribute type\
        manager.
    :raise HTTP_400_BAD_REQUEST: If nothing to delete.
    :return None: None
    """
    await attribute_type_dao.delete_all_by_names(attribute_types_names)
    await session.commit()
