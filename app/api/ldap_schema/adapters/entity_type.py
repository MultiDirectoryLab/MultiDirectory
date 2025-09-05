"""File for LDAPEntityTypeFastAPIAdapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import status

from api.base_adapter import BaseAdapter
from api.ldap_schema import LimitedListType
from api.ldap_schema.schema import (
    EntityTypePaginationSchema,
    EntityTypeSchema,
    EntityTypeUpdateSchema,
)
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.exceptions import (
    EntityTypeCantModifyError,
    EntityTypeNotFoundError,
    ObjectClassNotFoundError,
)
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams


class LDAPEntityTypeFastAPIAdapter(BaseAdapter[EntityTypeDAO]):
    """Adapter for LDAProuter."""

    _exceptions_map: dict[type[Exception], int] = {
        EntityTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        EntityTypeCantModifyError: status.HTTP_403_FORBIDDEN,
        ObjectClassNotFoundError: status.HTTP_404_NOT_FOUND,
    }

    async def modify_one_entity_type(
        self,
        entity_type_name: str,
        request_data: EntityTypeUpdateSchema,
    ) -> None:
        """Modify an Entity Type.

        \f
        :param str entity_type_name: Name of the Entity Type for modifying.
        :param EntityTypeUpdateDTO request_data: Changed data.
        :return None.
        """
        try:
            entity_type = await self._service.get_one_by_name(
                entity_type_name=entity_type_name,
            )
        except EntityTypeNotFoundError:
            raise EntityTypeCantModifyError

        if entity_type.is_system:
            raise EntityTypeCantModifyError(
                f"Entity Type '{entity_type_name}' is system and "
                f"cannot be modified.",
            )
        if request_data.name != entity_type.name:
            await self._service.validate_name(
                name=request_data.name,
            )
        await self._service.update(
            _id=entity_type.get_id(),
            dto=EntityTypeDTO(
                id=entity_type.get_id(),
                name=request_data.name,
                object_class_names=request_data.object_class_names,
                is_system=entity_type.is_system,
            ),
        )

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
        await self._service.create(
            EntityTypeDTO(
                id=None,
                name=request_data.name,
                object_class_names=request_data.object_class_names,
                is_system=is_system,
            ),
        )

    async def get_entity_type_attributes(
        self,
        entity_type_name: str,
    ) -> list[str]:
        """Get all attribute names for an Entity Type.

        \f
        :param str entity_type_name: Entity Type name.
        :return list[str]: List of attribute names.
        """
        return await self._service.get_entity_type_attributes(entity_type_name)

    async def delete_bulk_entity_types(
        self,
        entity_type_names: LimitedListType,
    ) -> None:
        """Delete multiple Entity Types.

        \f
        :param LimitedListType entity_type_names: Names of the
        Entity Types to delete.
        :return None.
        """
        await self._service.delete_all_by_names(
            entity_type_names=entity_type_names,
        )
