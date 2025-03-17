"""Attribute Type management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import DishkaRoute, FromDishka
from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from ldap_protocol.ldap_schema.attribute_type_uow import (
    AttributeTypeSchema,
    create_attribute_type,
    delete_attribute_types_by_names,
    get_all_attribute_types,
    get_attribute_type_by_name,
    modify_attribute_type,
)

attribute_type_router = APIRouter(
    prefix="/attribute_type",
    tags=["Attribute Type"],
    dependencies=[Depends(get_current_user)],
    route_class=DishkaRoute,
)


@attribute_type_router.post(
    "",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_attribute_type(
    request_data: AttributeTypeSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Create a new attribute type.

    :param AttributeTypeSchema request_data: Data for creating attribute type.
    :param FromDishka[AsyncSession] session: Database session.
    :return None.
    """
    await create_attribute_type(
        oid=request_data.oid,
        name=request_data.name,
        syntax=request_data.syntax,
        single_value=request_data.single_value,
        no_user_modification=request_data.no_user_modification,
        is_system=request_data.is_system,
        session=session,
    )


@attribute_type_router.get(
    "",
    response_model=list[AttributeTypeSchema],
    status_code=status.HTTP_200_OK,
)
async def get_list_attribute_types(
    session: FromDishka[AsyncSession],
) -> list[AttributeTypeSchema]:
    """Retrieve a list of all attribute types.

    :param FromDishka[AsyncSession] session: Database session.
    :return list[AttributeTypeSchema]: List of Attribute Type Schemas.
    """
    return [
        AttributeTypeSchema(
            oid=attribute_type.oid,
            name=attribute_type.name,
            syntax=attribute_type.syntax,
            single_value=attribute_type.single_value,
            no_user_modification=attribute_type.no_user_modification,
            is_system=attribute_type.is_system,
        )
        for attribute_type in await get_all_attribute_types(session)
    ]


@attribute_type_router.patch(
    "/{attribute_type_name}",
    status_code=status.HTTP_200_OK,
)
async def modify_one_attribute_type(
    attribute_type_name: str,
    request_data: AttributeTypeSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Modify an Attribute Type.

    :param str attribute_type_name: name of the attribute type for modifying.
    :param AttributeTypeSchema request_data: Changed data.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_404_NOT_FOUND: If attribute type not found.
    :raise HTTP_400_BAD_REQUEST: If field cannot be changed.
    :return None.
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

    for field_name, new_value in request_data.model_dump().items():
        if (
            field_name in {"oid", "name"}
            and getattr(attribute_type, field_name) != new_value
        ):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Field '{field_name}' cannot be changed.",
            )

    await modify_attribute_type(
        attribute_type=attribute_type,
        new_statement=request_data,
        session=session,
    )


@attribute_type_router.post(
    "/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_attribute_types(
    attribute_types_names: Annotated[list[str], Body(embed=True)],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete attribute types by their names.

    :param list[str] attribute_types_names: List of attribute types names.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_400_BAD_REQUEST: If nothing to delete.
    :return None: None
    """
    if not attribute_types_names:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Attribute Type names not found.",
        )

    await delete_attribute_types_by_names(attribute_types_names, session)
