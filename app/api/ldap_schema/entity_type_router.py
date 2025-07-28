"""Entity Type management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import HTTPException, Query, status
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
from ldap_protocol.utils.pagination import PaginationParams

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
    """Create a new Entity Type.

    \f
    :param EntityTypeSchema request_data: Data for creating Entity Type.
    :param FromDishka[EntityTypeDAO] entity_type_dao: Entity Type DAO.
    :param FromDishka[ObjectClassDAO] object_class_dao: Object Class DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :return None.
    """
    await object_class_dao.is_all_object_classes_exists(
        request_data.object_class_names
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
    :return EntityTypeSchema: Entity Type Schema.
    """
    entity_type = await entity_type_dao.get_one_by_name(entity_type_name)
    return EntityTypeSchema.model_validate(entity_type, from_attributes=True)


@ldap_schema_router.get(
    "/entity_types",
    response_model=EntityTypePaginationSchema,
    status_code=status.HTTP_200_OK,
)
async def get_list_entity_types_with_pagination(
    entity_type_dao: FromDishka[EntityTypeDAO],
    params: Annotated[PaginationParams, Query()],
) -> EntityTypePaginationSchema:
    """Retrieve a chunk of Entity Types with pagination.

    \f
    :param FromDishka[EntityTypeDAO] entity_type_dao: Entity Type DAO.
    :param PaginationParams params: Pagination parameters.
    :return EntityTypePaginationSchema: Paginator Schema.
    """
    pagination_result = await entity_type_dao.get_paginator(params=params)

    items = [
        EntityTypeSchema.model_validate(item, from_attributes=True)
        for item in pagination_result.items
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
    """Modify an Entity Type.

    \f
    :param str entity_type_name: Name of the Entity Type for modifying.
    :param EntityTypeUpdateSchema request_data: Changed data.
    :param FromDishka[EntityTypeDAO] entity_type_dao: Entity Type DAO.
    :param FromDishka[ObjectClassDAO] object_class_dao: Object Class DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :return None.
    """
    try:
        entity_type = await entity_type_dao.get_one_by_name(entity_type_name)

        await entity_type_dao.modify_one(
            entity_type=entity_type,
            new_statement=request_data,
            object_class_dao=object_class_dao,
        )
        await session.commit()
    except entity_type_dao.EntityTypeCantModifyError as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(error),
        )


@ldap_schema_router.post(
    "/entity_type/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_entity_types(
    entity_type_names: LimitedListType,
    entity_type_dao: FromDishka[EntityTypeDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete Entity Types by their names.

    \f
    :param LimitedListType entity_type_names: List of Entity Type names.
    :param FromDishka[EntityTypeDAO] entity_type_dao: Entity Type DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :return None: None
    """
    await entity_type_dao.delete_all_by_names(entity_type_names)
    await session.commit()
