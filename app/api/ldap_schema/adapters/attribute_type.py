"""Attribute Type management routers.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import status

from api.base_adapter import BaseAdapter
from api.ldap_schema import LimitedListType
from api.ldap_schema.constants import (
    DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM,
    DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
    DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
)
from api.ldap_schema.schema import (
    AttributeTypePaginationSchema,
    AttributeTypeRequestSchema,
    AttributeTypeSchema,
    AttributeTypeUpdateSchema,
)
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
    AttributeTypeCantModifyError,
    AttributeTypeNotFoundError,
)
from ldap_protocol.utils.pagination import PaginationParams


class AttributeTypeFastAPIAdapter(BaseAdapter[AttributeTypeDAO]):
    """Attribute Type management routers."""

    _exceptions_map: dict[type[Exception], int] = {
        AttributeTypeAlreadyExistsError: status.HTTP_409_CONFLICT,
        AttributeTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        AttributeTypeCantModifyError: status.HTTP_403_FORBIDDEN,
    }

    async def create(
        self,
        request_data: AttributeTypeRequestSchema,
    ) -> None:
        """Create a new Attribute Type.

        :param AttributeTypeRequestSchema request_data:
            Data for creating Attribute Type.
        :return None.
        """
        await self._service.create(
            AttributeTypeDTO(
                oid=request_data.oid,
                name=request_data.name,
                syntax=DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
                single_value=request_data.single_value,
                no_user_modification=DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
                is_system=DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM,
            ),
        )

    async def get(
        self,
        attribute_type_name: str,
    ) -> AttributeTypeSchema:
        """Get a single Attribute Type by name."""
        attribute_type = await self._service.get_one_by_name(
            attribute_type_name,
        )
        return AttributeTypeSchema.model_validate(
            attribute_type,
            from_attributes=True,
        )

    async def get_list_paginated(
        self,
        params: PaginationParams,
    ) -> AttributeTypePaginationSchema:
        """Get a list of Attribute Types with pagination."""
        pagination_result = await self._service.get_paginator(params)
        items = [
            AttributeTypeSchema.model_validate(
                item,
                from_attributes=True,
            )
            for item in pagination_result.items
        ]
        return AttributeTypePaginationSchema(
            metadata=pagination_result.metadata,
            items=items,
        )

    async def update(
        self,
        attribute_type_name: str,
        request_data: AttributeTypeUpdateSchema,
    ) -> None:
        """Modify an Attribute Type."""
        attribute_type = await self._service.get_one_by_name(
            attribute_type_name,
        )
        await self._service.update(
            _id=attribute_type.get_id(),
            dto=AttributeTypeDTO(
                id=attribute_type.get_id(),
                oid=attribute_type.oid,
                name=attribute_type.name,
                syntax=DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
                single_value=request_data.single_value,
                no_user_modification=DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
                is_system=attribute_type.is_system,
            ),
        )

    async def delete_bulk(
        self,
        attribute_types_names: LimitedListType,
    ) -> None:
        """Delete bulk Attribute Types."""
        await self._service.delete_all_by_names(attribute_types_names)
