"""EntityType management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.ldap_schema import LimitedListType
from api.ldap_schema.object_class_router import ldap_schema_router
from ldap_protocol.ldap_schema.entity_type_dao import (
    EntityTypeDAO,
    EntityTypePaginationSchema,
    EntityTypeSchema,
    EntityTypeUpdateSchema,
)
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import (
    PaginationParams,
    get_pagination_params,
)

_DEFAULT_ENTITY_TYPE_IS_SYSTEM = False


@ldap_schema_router.post(
    "/entity_type",
    status_code=status.HTTP_201_CREATED,
)
async def create_one_entity_type(
    request_data: EntityTypeSchema,
    entity_type_dao: FromDishka[EntityTypeDAO],
    object_class_dao: FromDishka[ObjectClassDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Create a new EntityType.

    \f
    :param EntityTypeSchema request_data: Data for creating EntityType.
    :param FromDishka[EntityTypeDAO] entity_type_dao: Entity Type DAO.
    :param FromDishka[ObjectClassDAO] object_class_dao: Object Class DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_400_BAD_REQUEST: If Object Classes not found.
    :return None.
    """
    if not await object_class_dao.is_all_object_classes_exists(
        request_data.object_class_names
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Object Classes not found.",
        )

    await entity_type_dao.create_one(
        name=request_data.name,
        is_system=_DEFAULT_ENTITY_TYPE_IS_SYSTEM,
        object_class_names=request_data.object_class_names,
    )
    await session.commit()


@ldap_schema_router.get(
    "/entity_type/{entity_type_name}",
    response_model=EntityTypeSchema,
    status_code=status.HTTP_200_OK,
)
async def get_one_entity_type(
    entity_type_name: str,
    entity_type_dao: FromDishka[EntityTypeDAO],
) -> EntityTypeSchema:
    """Retrieve a one Entity Type.

    \f
    :param str entity_type_name: name of the Entity Type.
    :param FromDishka[EntityTypeDAO] entity_type_dao: Entity Type DAO.
    :raise HTTP_404_NOT_FOUND: If Entity Type not found.
    :return EntityTypeSchema: One Entity Type Schemas.
    """
    entity_type = await entity_type_dao.get_one_by_name(entity_type_name)

    if not entity_type:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "EntityType not found.",
        )

    return EntityTypeSchema.from_db(entity_type)


@ldap_schema_router.get(
    "/entity_types",
    response_model=EntityTypePaginationSchema,
    status_code=status.HTTP_200_OK,
)
async def get_list_entity_types_with_pagination(
    entity_type_dao: FromDishka[EntityTypeDAO],
    params: Annotated[PaginationParams, Depends(get_pagination_params)],
) -> EntityTypePaginationSchema:
    """Retrieve a list of all entity types with pagination.

    \f
    :param FromDishka[EntityTypeDAO] entity_type_dao: Entity Type DAO.
    :param PaginationParams params: Pagination parameters.
    :return EntityTypePaginationSchema: Paginator.
    """
    pagination_result = await entity_type_dao.get_paginator(params=params)

    items = [
        EntityTypeSchema.from_db(item) for item in pagination_result.items
    ]
    return EntityTypePaginationSchema(
        metadata=pagination_result.metadata,
        items=items,
    )


@ldap_schema_router.patch(
    "/entity_type/{entity_type_name}",
    status_code=status.HTTP_200_OK,
)
async def modify_one_entity_type(
    entity_type_name: str,
    request_data: EntityTypeUpdateSchema,
    entity_type_dao: FromDishka[EntityTypeDAO],
    object_class_dao: FromDishka[ObjectClassDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Modify an EntityType.

    \f
    :param str entity_type_name: Name of the EntityType for modifying.
    :param EntityTypeUpdateSchema request_data: Changed data.
    :param FromDishka[EntityTypeDAO] entity_type_dao: Entity Type DAO.
    :param FromDishka[ObjectClassDAO] object_class_dao: Object Class DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_404_NOT_FOUND: If nothing to delete.
    :raise HTTP_400_BAD_REQUEST: If Object Classes not found.
    :return None.
    """
    entity_type = await entity_type_dao.get_one_by_name(entity_type_name)
    if not entity_type:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "EntityType not found.",
        )

    if not await object_class_dao.is_all_object_classes_exists(
        request_data.object_class_names
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Object Classes not found.",
        )

    await entity_type_dao.modify_one(
        entity_type=entity_type,
        new_statement=request_data,
    )
    await session.commit()


@ldap_schema_router.post(
    "/entity_type/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_entity_types(
    entity_type_names: LimitedListType,
    entity_type_dao: FromDishka[EntityTypeDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete EntityTypes by their names.

    \f
    :param LimitedListType entity_type_names: List of EntityTypes names.
    :param FromDishka[EntityTypeDAO] entity_type_dao: Entity Type DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :raise HTTP_400_BAD_REQUEST: If nothing to delete.
    :return None: None
    """
    await entity_type_dao.delete_all_by_names(entity_type_names)
    await session.commit()
