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
    AttributeTypeSchema,
    AttributeTypeUpdateSchema,
    create_attribute_type,
    delete_attribute_types_by_names,
    get_all_attribute_types,
    get_attribute_type_by_name,
    modify_attribute_type,
)


@ldap_schema_router.post(
    "/attribute_type",
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
        is_system=False,
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
    """Retrieve a list of all attribute types.

    :param str attribute_type_name: name of the Attribute Type.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_404_NOT_FOUND: If Attribute Type not found.
    :return AttributeTypeSchema: One Attribute Type Schemas.
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

    return AttributeTypeSchema(
        oid=attribute_type.oid,
        name=attribute_type.name,
        syntax=attribute_type.syntax,
        single_value=attribute_type.single_value,
        no_user_modification=attribute_type.no_user_modification,
        is_system=attribute_type.is_system,
    )


@ldap_schema_router.get(
    "/attribute_types",
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


@ldap_schema_router.patch(
    "/attribute_type/{attribute_type_name}",
    status_code=status.HTTP_200_OK,
)
async def modify_one_attribute_type(
    attribute_type_name: str,
    request_data: AttributeTypeUpdateSchema,
    session: FromDishka[AsyncSession],
) -> None:
    """Modify an Attribute Type.

    :param str attribute_type_name: name of the attribute type for modifying.
    :param AttributeTypeUpdateSchema request_data: Changed data.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_404_NOT_FOUND: If attribute type not found.
    :raise HTTP_400_BAD_REQUEST: If attribute type is system->cannot be changed
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

    if attribute_type.is_system:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "System attribute type cannot be modified.",
        )

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
