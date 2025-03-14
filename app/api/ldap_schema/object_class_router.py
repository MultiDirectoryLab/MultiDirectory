"""Object Class management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import DishkaRoute, FromDishka
from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from ldap_protocol.ldap_schema.object_class_uow import (
    ObjectClassSchema,
    create_object_class,
    delete_object_classes_by_names,
    get_all_object_classes,
    get_object_class_by_name,
    get_object_classes_by_names,
    modify_object_class,
)

object_class_router = APIRouter(
    prefix="/object_class",
    tags=["Object Class"],
    dependencies=[Depends(get_current_user)],
    route_class=DishkaRoute,
)


@object_class_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_object_class(
    request_data: ObjectClassSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Create a new Object Class.

    :param ObjectClassSchema request_data: Data for creating Object Class.
    :param FromDishka[AsyncSession] session: Database session.
    :return None.
    """
    await create_object_class(
        oid=request_data.oid,
        name=request_data.name,
        superior=request_data.superior,
        kind=request_data.kind,
        is_system=request_data.is_system,
        attribute_types_must=request_data.attribute_types_must,
        attribute_types_may=request_data.attribute_types_may,
        session=session,
    )


@object_class_router.get(
    "",
    response_model=list[ObjectClassSchema],
    status_code=status.HTTP_200_OK,
)
async def get_list_object_classes(
    session: FromDishka[AsyncSession],
) -> list[ObjectClassSchema]:
    """Retrieve a list of all Object Classes.

    :param FromDishka[AsyncSession] session: Database session.
    :return list[ObjectClassSchema]: List of object classes.
    """
    return [
        ObjectClassSchema(
            oid=object_class.oid,
            name=object_class.name,
            superior=object_class.superior,
            kind=object_class.kind,
            is_system=object_class.is_system,
            attribute_types_must=object_class.attribute_types_must_display,
            attribute_types_may=object_class.attribute_types_may_display,
        )
        for object_class in await get_all_object_classes(session)
    ]


@object_class_router.patch(
    "/{object_class_name}",
    status_code=status.HTTP_200_OK,
)
async def modify_one_object_class(
    object_class_name: str,
    request_data: ObjectClassSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Modify an Object Class.

    :param str object_class_name: Name of the Object Class for modifying.
    :param ObjectClassSchema request_data: Changed data.
    :param FromDishka[AsyncSession] session: Database session.
    :return None.
    """
    object_class = await get_object_class_by_name(object_class_name, session)
    if not object_class:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Object Class not found.",
        )

    await modify_object_class(changed_data=request_data, session=session)


@object_class_router.post(
    "/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_object_classes(
    object_classes_names: Annotated[list[str], Body(embed=True)],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete Object Classes by their names.

    :param list[str] object_classes_names: List of Object Classes names.
    :param FromDishka[AsyncSession] session: Database session.
    :return None: None
    """
    if not object_classes_names:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Object Classes not found.",
        )

    object_classes_names_exists = set(
        object_class.name
        for object_class in await get_object_classes_by_names(
            object_classes_names,
            session,
        )
    )

    diff = set(object_classes_names) - object_classes_names_exists
    if diff:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Object Classes not found: {diff}",
        )

    await delete_object_classes_by_names(object_classes_names, session)
