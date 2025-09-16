"""Base LDAP Schema Adapter Interface.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from __future__ import annotations

from dataclasses import Field
from typing import ClassVar, Generic, Protocol, TypeVar

from pydantic import BaseModel

from api.ldap_schema import LimitedListType
from ldap_protocol.utils.pagination import (
    BasePaginationSchema,
    PaginationParams,
    PaginationResult,
)


class _DataclassInstance(Protocol):
    __dataclass_fields__: ClassVar[dict[str, Field[object]]]


DtoT = TypeVar("DtoT", bound=_DataclassInstance)


class _ServiceProtocol(Protocol[DtoT]):
    """Protocol for service layer operations."""

    async def create(self, dto: DtoT) -> None:
        """Create a new entity."""
        ...

    async def get(self, _id: str) -> DtoT:
        """Get entity by ID."""
        ...

    async def get_paginator(
        self,
        params: PaginationParams,
    ) -> PaginationResult:
        """Get paginated entities."""
        ...

    async def update(self, _id: str, dto: DtoT) -> None:
        """Update entity."""
        ...

    async def delete_all_by_names(self, names: list[str]) -> None:
        """Delete multiple entities by names."""
        ...


ServiceT = TypeVar("ServiceT", bound=_ServiceProtocol)
SchemaT = TypeVar("SchemaT", bound=BaseModel)
UpdateSchemaT = TypeVar("UpdateSchemaT", bound=BaseModel)
PaginationSchemaT = TypeVar("PaginationSchemaT", bound=BasePaginationSchema)


class BaseLDAPSchemaAdapter(
    Generic[
        ServiceT,
        SchemaT,
        UpdateSchemaT,
        PaginationSchemaT,
        DtoT,
    ],
):
    """Base interface for LDAP Schema adapters with ClassVar behavior."""

    _service: ServiceT
    _pagination_schema: type[PaginationSchemaT]

    _converter_to_dto: staticmethod[[SchemaT], DtoT]
    _converter_to_schema: staticmethod[[DtoT], SchemaT]
    _converter_update_sch_to_dto: staticmethod[[UpdateSchemaT], DtoT]

    async def create(
        self,
        request_data: SchemaT,
    ) -> None:
        """Create a new entity.

        :param request_data: Data for creating entity.
        """
        dto = self._converter_to_dto(request_data)
        await self._service.create(dto)

    async def get(
        self,
        name: str,
    ) -> SchemaT:
        """Get a single entity by name.

        :param str name: Name of the entity.
        :return: Entity schema.
        """
        attribute_type = await self._service.get(name)
        return self._converter_to_schema(attribute_type)

    async def get_list_paginated(
        self,
        params: PaginationParams,
    ) -> PaginationSchemaT:
        """Get a list of entities with pagination.

        :param PaginationParams params: Pagination parameters.
        :return: Paginated result schema.
        """
        pagination_result = await self._service.get_paginator(params)

        items: list[SchemaT] = [
            self._converter_to_schema(item) for item in pagination_result.items
        ]

        return self._pagination_schema(
            metadata=pagination_result.metadata,
            items=items,
        )

    async def update(
        self,
        name: str,
        data: UpdateSchemaT,
    ) -> None:
        """Modify an entity.

        :param str name: Name of the entity to modify.
        :param data: Updated data.
        """
        dto = self._converter_update_sch_to_dto(data)
        await self._service.update(name, dto)

    async def delete_bulk(
        self,
        names: LimitedListType,
    ) -> None:
        """Delete multiple entities.

        :param LimitedListType names: Names of entities to delete.
        """
        await self._service.delete_all_by_names(names)
