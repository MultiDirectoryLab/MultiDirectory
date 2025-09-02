"""Attribute Type management routers.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from api.base_adapter import BaseAdapter
from api.ldap_schema import LimitedListType
from api.ldap_schema.schema import (
    AttributeTypePaginationSchema,
    AttributeTypeSchema,
    AttributeTypeUpdateSchema,
)
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.dto import (
    AttributeTypeDTO,
    AttributeTypeUpdateDTO,
)
from ldap_protocol.ldap_schema.exceptions import (
    AttributeTypeAlreadyExistsError,
    AttributeTypeCantModifyError,
    AttributeTypeNotFoundError,
)
from ldap_protocol.utils.pagination import PaginationParams


class AttributeTypeFastAPIAdapter(BaseAdapter[AttributeTypeDAO]):
    """Attribute Type management routers."""

    _DEFAULT_ATTRIBUTE_TYPE_SYNTAX = "1.3.6.1.4.1.1466.115.121.1.15"
    _DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD = False
    _DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM = False
    _exceptions_map: dict[type[Exception], int] = {
        AttributeTypeAlreadyExistsError: status.HTTP_409_CONFLICT,
        AttributeTypeNotFoundError: status.HTTP_404_NOT_FOUND,
        AttributeTypeCantModifyError: status.HTTP_403_FORBIDDEN,
    }

    def __init__(
        self,
        service: AttributeTypeDAO,
        session: AsyncSession,
        dao: AttributeTypeDAO,
    ) -> None:
        """Initialize dependencies via DI.

        :param AttributeTypeDAO service: Attribute Type DAO.
        :param AsyncSession session: Database session.
        :param AttributeTypeDAO dao: Attribute Type DAO.
        """
        super().__init__(service)
        self._session = session
        self._dao = dao

    async def create_one_attribute_type(
        self,
        request_data: AttributeTypeSchema,
    ) -> None:
        """Create a new Attribute Type.

        :param AttributeTypeSchema request_data:
            Data for creating Attribute Type.
        :return None.
        """
        await self._dao.create(
            AttributeTypeDTO(
                id=0,
                oid=request_data.oid,
                name=request_data.name,
                syntax=self._DEFAULT_ATTRIBUTE_TYPE_SYNTAX,
                single_value=request_data.single_value,
                no_user_modification=self._DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD,
                is_system=self._DEFAULT_ATTRIBUTE_TYPE_IS_SYSTEM,
            ),
        )

    async def get_one_attribute_type(
        self,
        attribute_type_name: str,
    ) -> AttributeTypeSchema:
        """Get a single Attribute Type by name."""
        attribute_type = await self._dao.get_one_by_name(attribute_type_name)
        return AttributeTypeSchema.model_validate(
            attribute_type,
            from_attributes=True,
        )

    async def get_list_attribute_types_with_pagination(
        self,
        params: PaginationParams,
    ) -> AttributeTypePaginationSchema:
        """Get a list of Attribute Types with pagination."""
        pagination_result = await self._dao.get_paginator(params)
        items = [
            AttributeTypeSchema.model_validate(item, from_attributes=True)
            for item in pagination_result.items
        ]
        return AttributeTypePaginationSchema(
            metadata=pagination_result.metadata,
            items=items,
        )

    async def modify_one_attribute_type(
        self,
        attribute_type_name: str,
        request_data: AttributeTypeUpdateSchema,
    ) -> None:
        """Modify an Attribute Type."""
        attribute_type = await self._dao.get_one_by_name(
            attribute_type_name,
        )

        request_data.syntax = self._DEFAULT_ATTRIBUTE_TYPE_SYNTAX
        request_data.no_user_modification = (
            self._DEFAULT_ATTRIBUTE_TYPE_NO_USER_MOD
        )
        await self._dao.modify_one(
            attribute_type=attribute_type,
            new_statement=AttributeTypeUpdateDTO(
                syntax=request_data.syntax,
                single_value=request_data.single_value,
                no_user_modification=request_data.no_user_modification,
            ),
        )

    async def delete_bulk_attribute_types(
        self,
        attribute_types_names: LimitedListType,
    ) -> None:
        """Delete bulk Attribute Types."""
        await self._dao.delete_all_by_names(attribute_types_names)
