"""Attribute Type management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import DishkaRoute, FromDishka
from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_current_user
from ldap_protocol.ldap_schema.attribute_type import (
    AttributeTypeSchema,
    create_attribute_type,
    delete_attribute_types,
    get_attribute_type,
    get_attribute_types,
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
    """Create a new access policy.

    :param AttributeTypeSchema request_data: Data for creating access policy.
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
    :return list[AccessPolicyMaterialSchema]: List of access policies.
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
        for attribute_type in await get_attribute_types(session)
    ]


@attribute_type_router.patch(
    "/{attribute_type_oid}",
    status_code=status.HTTP_200_OK,
)
async def modify_one_attribute_type(
    attribute_type_oid: int,
    request_data: AttributeTypeSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Modify an Attribute Type.

    :param int attribute_type_oid: OID of the attribute type.
    :param AttributeTypeSchema request_data: Data for modifying.
    :param FromDishka[AsyncSession] session: Database session.
    :return None.
    """
    attribute_type = await get_attribute_type(attribute_type_oid, session)
    if not attribute_type:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Attribute Type not found.",
        )

    await modify_attribute_type(
        attribute_type=attribute_type,
        attribute_type_schema=request_data,
        session=session,
    )


@attribute_type_router.post(
    "/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_attribute_types(
    attribute_types_oids: Annotated[list[str], Body(embed=True)],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete attribute types by their OIDs.

    :param list[str] attribute_types_oids: List of attribute types OIDs.
    :param FromDishka[AsyncSession] session: Database session.
    :return None: None
    """
    if not attribute_types_oids:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "Access Policies not found.",
        )

    await delete_attribute_types(attribute_types_oids, session)
