"""Entity Type management routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.ldap_schema import LimitedListType
from api.ldap_schema.object_class_router import ldap_schema_router
from api.main.adapters.ldap_entity_type import LDAPEntityTypeAdapter
from ldap_protocol.ldap_schema.entity_type_dao import (
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
    adapter: FromDishka[LDAPEntityTypeAdapter],
    object_class_dao: FromDishka[ObjectClassDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Create a new Entity Type.

    \f
    :param EntityTypeSchema request_data: Data for creating Entity Type.
    :param FromDishka[LDAPEntityTypeAdapter] adapter: LDAPEntityTypeAdapter
    instance.
    :param FromDishka[ObjectClassDAO] object_class_dao: Object Class DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :return None.
    """
    await adapter.create_one_entity_type(
        request_data=request_data,
        is_system=_DEFAULT_ENTITY_TYPE_IS_SYSTEM,
        object_class_dao=object_class_dao,
        session=session,
    )


@ldap_schema_router.get(
    "/entity_type/{entity_type_name}",
    response_model=EntityTypeSchema,
    status_code=status.HTTP_200_OK,
)
async def get_one_entity_type(
    entity_type_name: str,
    ldap_entity_type_adapter: FromDishka[LDAPEntityTypeAdapter],
) -> EntityTypeSchema:
    """Retrieve a one Entity Type.

    \f
    :param str entity_type_name: name of the Entity Type.
    :param FromDishka[LDAPEntityTypeAdapter] adapter: LDAPEntityTypeAdapter
    instance.
    :return EntityTypeSchema: Entity Type Schema.
    """
    return await ldap_entity_type_adapter.get_one_entity_type(entity_type_name)


@ldap_schema_router.get(
    "/entity_types",
    response_model=EntityTypePaginationSchema,
    status_code=status.HTTP_200_OK,
)
async def get_list_entity_types_with_pagination(
    ldap_entity_type_adapter: FromDishka[LDAPEntityTypeAdapter],
    params: Annotated[PaginationParams, Query()],
) -> EntityTypePaginationSchema:
    """Retrieve a chunk of Entity Types with pagination.

    \f
    :param FromDishka[LDAPEntityTypeAdapter] adapter: LDAPEntityTypeAdapter
    instance.
    :param PaginationParams params: Pagination parameters.
    :return EntityTypePaginationSchema: Paginator Schema.
    """
    return (
        await ldap_entity_type_adapter.get_list_entity_types_with_pagination(
            params=params,
        )
    )


@ldap_schema_router.patch(
    "/entity_type/{entity_type_name}",
    status_code=status.HTTP_200_OK,
)
async def modify_one_entity_type(
    entity_type_name: str,
    request_data: EntityTypeUpdateSchema,
    ldap_entity_type_adapter: FromDishka[LDAPEntityTypeAdapter],
    object_class_dao: FromDishka[ObjectClassDAO],
    session: FromDishka[AsyncSession],
) -> None:
    """Modify an Entity Type.

    \f
    :param str entity_type_name: Name of the Entity Type for modifying.
    :param EntityTypeUpdateSchema request_data: Changed data.
    :param FromDishka[LDAPEntityTypeAdapter] adapter: LDAPEntityTypeAdapter
    instance.
    :param FromDishka[ObjectClassDAO] object_class_dao: Object Class DAO.
    :param FromDishka[AsyncSession] session: Database session.
    :return None.
    """
    await ldap_entity_type_adapter.modify_one_entity_type(
        entity_type_name=entity_type_name,
        request_data=request_data,
        session=session,
        object_class_dao=object_class_dao,
    )


@ldap_schema_router.post(
    "/entity_type/delete",
    status_code=status.HTTP_200_OK,
)
async def delete_bulk_entity_types(
    entity_type_names: LimitedListType,
    ldap_entity_type_adapter: FromDishka[LDAPEntityTypeAdapter],
    session: FromDishka[AsyncSession],
) -> None:
    """Delete Entity Types by their names.

    \f
    :param LimitedListType entity_type_names: List of Entity Type names.
    :param FromDishka[LDAPEntityTypeAdapter] adapter: LDAPEntityTypeAdapter
    instance.
    :param FromDishka[AsyncSession] session: Database session.
    :return None: None
    """
    await ldap_entity_type_adapter.delete_bulk_entity_types(
        entity_type_names=entity_type_names,
        session=session,
    )
