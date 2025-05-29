"""Object Class management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka.integrations.fastapi import FromDishka
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.ldap_schema import LimitedListType
from api.ldap_schema.attribute_type_router import ldap_schema_router
from ldap_protocol.ldap_schema.attribute_type_crud import AttributeTypeDAO
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
    attribute_type_manager: FromDishka[AttributeTypeDAO],
) -> None:
    """Create a new Object Class.

    \f
    :param ObjectClassSchema request_data: Data for creating Object Class.
    :param FromDishka[AsyncSession] session: Database session.
    :return None.
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
        attribute_type_manager=attribute_type_manager,
    )
    await session.commit()


@ldap_schema_router.get(
    "/object_class/{object_class_name}",
    response_model=ObjectClassSchema,
    status_code=status.HTTP_200_OK,
)
async def get_one_object_class(
    object_class_name: str,
    session: FromDishka[AsyncSession],
) -> ObjectClassSchema:
    """Retrieve a one object class.

    \f
    :param str object_class_name: name of the Object Class.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_404_NOT_FOUND: If Object Class not found.
    :return ObjectClassSchema: One Object Class Schemas.
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
    """Retrieve a list of all object classes with paginate.

    \f
    :param int page_number: number of page.
    :param FromDishka[AsyncSession] session: Database session.
    :param int page_size: number of items per page.
    :return ObjectClassPaginationSchema: Paginator.
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
    attribute_type_manager: FromDishka[AttributeTypeDAO],
) -> None:
    """Modify an Object Class.

    \f
    :param str object_class_name: Name of the Object Class for modifying.
    :param ObjectClassUpdateSchema request_data: Changed data.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_404_NOT_FOUND: If nothing to delete.
    :raise HTTP_400_BAD_REQUEST: If object class is system->cannot be changed
    :return None.
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
        attribute_type_manager=attribute_type_manager,
    )
    await session.commit()


@ldap_schema_router.post(
    "/object_class/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_object_classes(
    object_classes_names: LimitedListType,
    session: FromDishka[AsyncSession],
) -> None:
    """Delete Object Classes by their names.

    \f
    :param list[str] object_classes_names: List of Object Classes names.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_400_BAD_REQUEST: If nothing to delete.
    :return None: None
    """
    await delete_object_classes_by_names(object_classes_names, session)
    await session.commit()
