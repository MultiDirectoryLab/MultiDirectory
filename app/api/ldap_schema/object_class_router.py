"""Object Class management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.ldap_schema import LimitedListType
from api.ldap_schema.attribute_type_router import ldap_schema_router
from ldap_protocol.ldap_schema.object_class_crud import (
    ObjectClassDAO,
    ObjectClassPaginationSchema,
    ObjectClassSchema,
    ObjectClassUpdateSchema,
)
from ldap_protocol.utils.pagination import (
    PaginationParams,
    get_pagination_params,
)

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
    """Create a new Object Class.

    \f
    :param ObjectClassSchema request_data: Data for creating Object Class.
    :param FromDishka[ObjectClassDAO] object_class_dao: Object Class DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :return None.
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
    """Retrieve a one object class.

    \f
    :param str object_class_name: name of the Object Class.
    :param FromDishka[ObjectClassDAO] object_class_dao: Object Class DAO.
    :raise HTTP_404_NOT_FOUND: If Object Class not found.
    :return ObjectClassSchema: One Object Class Schemas.
    """
    object_class = await object_class_dao.get_one_by_name(object_class_name)

    if not object_class:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Object Class not found.",
        )

    return ObjectClassSchema.from_db(object_class)


@ldap_schema_router.get(
    "/object_classes",
    response_model=ObjectClassPaginationSchema,
    status_code=status.HTTP_200_OK,
)
async def get_list_object_classes_with_pagination(
    object_class_dao: FromDishka[ObjectClassDAO],
    params: Annotated[PaginationParams, Depends(get_pagination_params)],
) -> ObjectClassPaginationSchema:
    """Retrieve a list of all object classes with paginate.

    \f
    :param FromDishka[ObjectClassDAO] object_class_dao: Object Class DAO.
    :param PaginationParams params: Pagination parameters.
    :return ObjectClassPaginationSchema: Paginator.
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
    """Modify an Object Class.

    \f
    :param str object_class_name: Name of the Object Class for modifying.
    :param ObjectClassUpdateSchema request_data: Changed data.
    :param FromDishka[ObjectClassDAO] object_class_dao: Object Class DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_404_NOT_FOUND: If nothing to delete.
    :raise HTTP_400_BAD_REQUEST: If object class is system->cannot be changed
    :return None.
    """
    object_class = await object_class_dao.get_one_by_name(object_class_name)
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
    """Delete Object Classes by their names.

    \f
    :param LimitedListType object_classes_names: List of Object Classes names.
    :param FromDishka[ObjectClassDAO] object_class_dao: Object Class DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_400_BAD_REQUEST: If nothing to delete.
    :return None: None
    """
    await object_class_dao.delete_all_by_names(object_classes_names)
    await session.commit()
