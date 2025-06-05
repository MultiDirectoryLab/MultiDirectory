"""Object Class management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Body, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.ldap_schema.attribute_type_router import ldap_schema_router
from ldap_protocol.ldap_schema.object_class_crud import (
    ObjectClassPaginationSchema,
    ObjectClassSchema,
    ObjectClassUpdateSchema,
    create_object_class,
    delete_object_classes_by_names,
    get_object_class_by_name,
    get_object_classes_paginator,
    modify_object_class,
)
from ldap_protocol.utils.pagination import PaginationParams

_DEFAULT_OBJECT_CLASS_IS_SYSTEM = False


@ldap_schema_router.post(
    "/object_class",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_object_class(
    request_data: ObjectClassSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Create a new object class.

    Args:
        request_data (ObjectClassSchema): Data for creating object class.
        session (AsyncSession): Database session.
    """
    await create_object_class(
        oid=request_data.oid,
        name=request_data.name,
        superior_name=request_data.superior_name,
        kind=request_data.kind,
        is_system=_DEFAULT_OBJECT_CLASS_IS_SYSTEM,
        attribute_type_names_must=request_data.attribute_type_names_must,
        attribute_type_names_may=request_data.attribute_type_names_may,
        session=session,
    )


@ldap_schema_router.get(
    "/object_class/{object_class_name}",
    response_model=ObjectClassSchema,
    status_code=status.HTTP_200_OK,
)
async def get_one_object_class(
    object_class_name: str,
    session: FromDishka[AsyncSession],
) -> ObjectClassSchema:
    """Retrieve a single object class by name.

    Args:
        object_class_name (str): Name of the object class.
        session (AsyncSession): Database session.

    Returns:
        ObjectClassSchema: Object class schema.

    Raises:
        HTTPException: If object class not found.
    """
    object_class = await get_object_class_by_name(
        object_class_name,
        session,
    )

    if not object_class:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Object Class not found.",
        )

    return ObjectClassSchema.from_db(object_class)


@ldap_schema_router.get(
    "/object_classes/{page_number}",
    response_model=ObjectClassPaginationSchema,
    status_code=status.HTTP_200_OK,
)
async def get_list_object_classes_with_pagination(
    page_number: int,
    session: FromDishka[AsyncSession],
    page_size: int = 25,
) -> ObjectClassPaginationSchema:
    """Retrieve a paginated list of object classes.

    Args:
        page_number (int): Page number.
        session (FromDishka[AsyncSession]): Database session.
        page_size (int): Number of items per page. Defaults to 25.

    Returns:
        ObjectClassPaginationSchema: Paginated object classes.
    """
    params = PaginationParams(
        page_number=page_number,
        page_size=page_size,
    )
    pagination_result = await get_object_classes_paginator(
        params=params,
        session=session,
    )

    items = [
        ObjectClassSchema.from_db(item) for item in pagination_result.items
    ]
    return ObjectClassPaginationSchema(
        metadata=pagination_result.metadata,
        items=items,
    )


@ldap_schema_router.patch(
    "/object_class/{object_class_name}",
    status_code=status.HTTP_200_OK,
)
async def modify_one_object_class(
    object_class_name: str,
    request_data: ObjectClassUpdateSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Modify an object class.

    Args:
        object_class_name (str): Name of the object class to modify.
        request_data (ObjectClassUpdateSchema): Data to update.
        session (AsyncSession): Database session.

    Raises:
        HTTPException: If object class not found or is a system object class.
    """
    object_class = await get_object_class_by_name(object_class_name, session)
    if not object_class:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Object Class not found.",
        )

    if object_class.is_system:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "System Object Class cannot be modified.",
        )

    await modify_object_class(
        object_class=object_class,
        new_statement=request_data,
        session=session,
    )


@ldap_schema_router.post(
    "/object_classes/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_object_classes(
    object_classes_names: Annotated[list[str], Body(embed=True)],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete object classes by their names.

    Args:
        object_classes_names (list[str]): List of object class names.
        session (AsyncSession): Database session.

    Raises:
        HTTPException: If no object class names are provided.
    """
    if not object_classes_names:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Object Classes not found.",
        )

    await delete_object_classes_by_names(object_classes_names, session)
