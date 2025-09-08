"""File for LDAPEntityTypeFastAPIAdapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import status

from api.base_adapter import BaseAdapter
from api.ldap_schema import LimitedListType
from api.ldap_schema.constants import DEFAULT_ENTITY_TYPE_IS_SYSTEM
from api.ldap_schema.schema import (
    EntityTypePaginationSchema,
    EntityTypeSchema,
    EntityTypeUpdateSchema,
)
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type_use_case import EntityTypeUseCase
from ldap_protocol.ldap_schema.exceptions import (
    EntityTypeCantModifyError,
    EntityTypeNotFoundError,
    ObjectClassNotFoundError,
)
from ldap_protocol.utils.pagination import PaginationParams


class LDAPEntityTypeFastAPIAdapter(BaseAdapter[EntityTypeUseCase]):
    """Adapter for LDAProuter."""

    _exceptions_map: dict[type[Exception], int] = {
        EntityTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        EntityTypeCantModifyError: status.HTTP_403_FORBIDDEN,
        ObjectClassNotFoundError: status.HTTP_404_NOT_FOUND,
    }

    async def update(
        self,
        name: str,
        request_data: EntityTypeUpdateSchema,
    ) -> None:
        """Modify an Entity Type.

        \f
        :param str name: Name of the Entity Type for modifying.
        :param EntityTypeUpdateDTO request_data: Changed data.
        :return None.
        """
        try:
            entity_type = await self._service.get_by_name(name=name)
        except EntityTypeNotFoundError:
            raise EntityTypeCantModifyError

        updated_entity_type = EntityTypeDTO(
            id=entity_type.id,
            name=request_data.name,
            object_class_names=request_data.object_class_names,
            is_system=entity_type.is_system,
        )

        await self._service.update(
            entity_type_dto=updated_entity_type,
            request_name=request_data.name,
        )

    async def get_paginated_entity(
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

    async def get_by_name(
        self,
        name: str,
    ) -> EntityTypeSchema:
        """Retrieve a one Entity Type.

        \f
        :param str name: name of the Entity Type.
        :return EntityTypeSchema: Entity Type Schema.
        """
        entity_type = await self._service.get_by_name(name=name)
        return EntityTypeSchema.model_validate(
            entity_type,
            from_attributes=True,
        )

    async def create(self, request_data: EntityTypeSchema) -> None:
        """Create a new Entity Type.

        \f
        :param EntityTypeSchema request_data: Data for creating
        a new Entity Type.
        :return None.
        """
        await self._service.create(
            EntityTypeDTO(
                name=request_data.name,
                is_system=DEFAULT_ENTITY_TYPE_IS_SYSTEM,
                object_class_names=request_data.object_class_names,
            ),
        )

    async def get_entity_type_attributes(
        self,
        name: str,
    ) -> list[str]:
        """Get all attribute names for an Entity Type.

        \f
        :param str name: Entity Type name.
        :return list[str]: List of attribute names.
        """
        return await self._service.get_entity_type_attributes(name)

    async def delete_bulk(self, names: LimitedListType) -> None:
        """Delete multiple Entity Types.

        \f
        :param LimitedListType names: Names of the
        Entity Types to delete.
        :return None.
        """
        await self._service.delete_all_by_names(names=names)
