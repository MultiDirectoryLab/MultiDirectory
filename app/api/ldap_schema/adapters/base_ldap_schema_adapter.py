"""Base LDAP Schema Adapter Interface.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Any, Callable, ClassVar, Protocol

from pydantic import BaseModel

from api.ldap_schema import LimitedListType
from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    PaginationParams,
)


class BaseLDAPSchema(Protocol):
    """Base interface for LDAP Schema adapters with ClassVar behavior."""

    _service: Any  # Service instance
    _schema: ClassVar[type[BaseModel]]
    _pagination_schema: ClassVar[type[BasePaginationSchema]]
    _request_schema: ClassVar[type[BaseModel]]
    _update_schema: ClassVar[type[BaseModel]]
    _dto: ClassVar[type[Any]]
    converter_to_dto: ClassVar[Callable[..., Any]]
    converter_to_schema: ClassVar[Callable[..., Any]]
    converter_to_base_schema: ClassVar[Callable[..., Any]]

    def _convert_schema_to_dto(self, schema: BaseModel) -> Any:
        """Convert schema to DTO using adaptix converter.

        :param schema: Schema instance to convert.
        :return: Converted DTO instance.
        """
        return type(self).converter_to_dto(schema)

    def _convert_dto_to_schema(self, dto: Any) -> BaseModel:
        """Convert DTO to schema using adaptix converter.

        :param dto: DTO instance to convert.
        :return: Converted schema instance.
        """
        return type(self).converter_to_schema(dto)

    def _convert_to_base_schema(
        self,
        base_schema: Any,
    ) -> Any:
        """Convert base schema to schema using adaptix converter.

        :param base_schema: Base schema instance to convert.
        :return: Converted schema instance.
        """
        return type(self).converter_to_base_schema(base_schema)

    async def create(
        self,
        request_data: Any,
    ) -> None:
        """Create a new entity.

        :param request_data: Data for creating entity.
        """
        dto = self._convert_schema_to_dto(request_data)
        await self._service.create(dto)

    async def get(
        self,
        name: str,
    ) -> BaseModel:
        """Get a single entity by name.

        :param str name: Name of the entity.
        :return: Entity schema.
        """
        attribute_type = await self._service.get_one_by_name(
            name,
        )
        return self._convert_dto_to_schema(attribute_type)

    async def get_list_paginated(
        self,
        params: PaginationParams,
    ) -> BasePaginationSchema:
        """Get a list of entities with pagination.

        :param PaginationParams params: Pagination parameters.
        :return: Paginated result schema.
        """
        pagination_result = await self._service.get_paginator(params)

        items = [
            self._convert_dto_to_schema(item)
            for item in pagination_result.items
        ]

        return self._pagination_schema(
            metadata=pagination_result.metadata,
            items=items,
        )

    async def update(
        self,
        name: str,
        request_data: Any,
    ) -> None:
        """Modify an entity.

        :param str name: Name of the entity to modify.
        :param request_data: Updated data.
        """
        entity = await self._service.get_one_by_name(name)
        schema = self._convert_to_base_schema(request_data)
        dto = self._convert_schema_to_dto(schema)

        await self._service.update(entity.id, dto)

    async def delete_bulk(
        self,
        names: LimitedListType,
    ) -> None:
        """Delete multiple entities.

        :param LimitedListType names: Names of entities to delete.
        """
        await self._service.delete_all_by_names(names)
