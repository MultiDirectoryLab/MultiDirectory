"""Object Class management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.ldap_schema import LimitedListType
from api.ldap_schema.attribute_type_router import ldap_schema_router
from ldap_protocol.ldap_schema.object_class_dao import (
    ObjectClassDAO,
    ObjectClassPaginationSchema,
    ObjectClassSchema,
    ObjectClassUpdateSchema,
)
from ldap_protocol.utils.pagination import PaginationParams

_DEFAULT_OBJECT_CLASS_IS_SYSTEM = False


@ldap_schema_router.post(
    "/object_class",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_object_class(
    request_data: ObjectClassSchema,
    object_class_dao: FromDishka[ObjectClassDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Create a new object class.

    Args:
        request_data (ObjectClassSchema): Data for creating object class.
        object_class_dao (ObjectClassDAO): Object Class DAO.
        session (AsyncSession): Database session.
    """
    await object_class_dao.create_one(
        oid=request_data.oid,
        name=request_data.name,
        superior_name=request_data.superior_name,
        kind=request_data.kind,
        is_system=_DEFAULT_OBJECT_CLASS_IS_SYSTEM,
        attribute_type_names_must=request_data.attribute_type_names_must,
        attribute_type_names_may=request_data.attribute_type_names_may,
    )
    await session.commit()


@ldap_schema_router.get(
    "/object_class/{object_class_name}",
    response_model=ObjectClassSchema,
    status_code=status.HTTP_200_OK,
)
async def get_one_object_class(
    object_class_name: str,
    object_class_dao: FromDishka[ObjectClassDAO],
) -> ObjectClassSchema:
    """Retrieve a single object class by name.

    Args:
        object_class_name (str): Name of the object class.
        object_class_dao (ObjectClassDAO): Object Class DAO.

    Returns:
        ObjectClassSchema: Object class schema.
    """
    object_class = await object_class_dao.get_one_by_name(object_class_name)

    return ObjectClassSchema.from_db(object_class)


@ldap_schema_router.get(
    "/object_classes",
    response_model=ObjectClassPaginationSchema,
    status_code=status.HTTP_200_OK,
)
async def get_list_object_classes_with_pagination(
    object_class_dao: FromDishka[ObjectClassDAO],
    params: Annotated[PaginationParams, Query()],
) -> ObjectClassPaginationSchema:
    """Retrieve a paginated list of object classes.

    Args:
        object_class_dao (ObjectClassDAO): Object Class DAO.
        params (PaginationParams): Pagination parameters.

    Returns:
        ObjectClassPaginationSchema: Paginated object classes.
    """
    pagination_result = await object_class_dao.get_paginator(params=params)

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
    object_class_dao: FromDishka[ObjectClassDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Modify an object class.

    Args:
        object_class_name (str): Name of the object class to modify.
        request_data (ObjectClassUpdateSchema): Data to update.
        object_class_dao (ObjectClassDAO): Object Class DAO.
        session (AsyncSession): Database session.
    """
    object_class = await object_class_dao.get_one_by_name(object_class_name)

    await object_class_dao.modify_one(
        object_class=object_class,
        new_statement=request_data,
    )
    await session.commit()


@ldap_schema_router.post(
    "/object_class/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_object_classes(
    object_classes_names: LimitedListType,
    object_class_dao: FromDishka[ObjectClassDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete object classes by their names.

    Args:
        object_classes_names (list[str]): List of object class names.
        object_class_dao (ObjectClassDAO): Object Class DAO.
        session (AsyncSession): Database session.
    """
    await object_class_dao.delete_all_by_names(object_classes_names)
    await session.commit()
