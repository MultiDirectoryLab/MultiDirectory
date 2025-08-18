"""File for LDAPEntityTypeAdapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ParamSpec, TypeVar

from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from api.base_adapter import BaseAdapter
from api.ldap_schema import LimitedListType
from ldap_protocol.ldap_schema.entity_type_dao import (
    EntityTypeDAO,
    EntityTypePaginationSchema,
    EntityTypeSchema,
    EntityTypeUpdateSchema,
)
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams

P = ParamSpec("P")
R = TypeVar("R")


# NOTE: This is a workaround for non refactored DAOs
class LDAPEntityTypeAdapter(BaseAdapter[EntityTypeDAO]):  # type: ignore
    """Adapter for LDAProuter."""

    _exceptions_map: dict[type[Exception], int] = {
        EntityTypeDAO.EntityTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        EntityTypeDAO.EntityTypeCantModifyError: status.HTTP_403_FORBIDDEN,
    }

    async def modify_one_entity_type(
        self,
        entity_type_name: str,
        request_data: EntityTypeUpdateSchema,
        object_class_dao: ObjectClassDAO,
        session: AsyncSession,
    ) -> None:
        """Modify an Entity Type.

        \f
        :param str entity_type_name: Name of the Entity Type for modifying.
        :param EntityTypeUpdateSchema request_data: Changed data.
        :param ObjectClassDAO object_class_dao: Object Class DAO.
        :param AsyncSession session: Database session.
        :return None.
        """
        await self._service.modify_one(
            entity_type_name=entity_type_name,
            new_statement=request_data,
            object_class_dao=object_class_dao,
        )
        await session.commit()

    async def get_list_entity_types_with_pagination(
        self,
        params: PaginationParams,
    ) -> EntityTypePaginationSchema:
        """Retrieve a chunk of Entity Types with pagination.

        \f
        :param PaginationParams params: Pagination parameters.
        :return EntityTypePaginationSchema: Paginator Schema.
        """
        pagination_result = await self._service.get_paginator(
            params=params,
        )

        items = [
            EntityTypeSchema.model_validate(item, from_attributes=True)
            for item in pagination_result.items
        ]
        return EntityTypePaginationSchema(
            metadata=pagination_result.metadata,
            items=items,
        )

    async def get_one_entity_type(
        self,
        entity_type_name: str,
    ) -> EntityTypeSchema:
        """Retrieve a one Entity Type.

        \f
        :param str entity_type_name: name of the Entity Type.
        :return EntityTypeSchema: Entity Type Schema.
        """
        entity_type = await self._service.get_one_by_name(
            entity_type_name=entity_type_name,
        )
        return EntityTypeSchema.model_validate(
            entity_type,
            from_attributes=True,
        )

    async def create_one_entity_type(
        self,
        request_data: EntityTypeSchema,
        object_class_dao: ObjectClassDAO,
        is_system: bool,
        session: AsyncSession,
    ) -> None:
        """Create a new Entity Type.

        \f
        :param EntityTypeSchema request_data: Data for creating
        a new Entity Type.
        :param ObjectClassDAO object_class_dao: Object Class DAO.
        :param AsyncSession session: Database session.
        :return None.
        """
        await object_class_dao.is_all_object_classes_exists(
            request_data.object_class_names,
        )
        await self._service.create_one(
            name=request_data.name,
            is_system=is_system,
            object_class_names=request_data.object_class_names,
        )
        await session.commit()

    async def delete_bulk_entity_types(
        self,
        entity_type_names: LimitedListType,
        session: AsyncSession,
    ) -> None:
        """Delete multiple Entity Types.

        \f
        :param LimitedListType entity_type_names: Names of the
        Entity Types to delete.
        :param AsyncSession session: Database session.
        :return None.
        """
        await self._service.delete_all_by_names(
            entity_type_names=entity_type_names,
        )
        await session.commit()
