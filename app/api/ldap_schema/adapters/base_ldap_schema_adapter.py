"""Base LDAP Schema Adapter Interface.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from typing import Any, Callable, Generic, TypeVar

from adaptix import P
from adaptix.conversion import (
    allow_unlinked_optional,
    get_converter,
    link_function,
)

from abstract_dao import AbstractDAO, AbstractService
from api.base_adapter import BaseAdapter
from api.ldap_schema import LimitedListType
from ldap_protocol.utils.pagination import PaginationParams

TService = TypeVar("TService", bound=AbstractDAO | AbstractService)
TSchema = TypeVar("TSchema")
TPaginationSchema = TypeVar("TPaginationSchema")
TRequestSchema = TypeVar("TRequestSchema")
TUpdateSchema = TypeVar("TUpdateSchema")
TDTO = TypeVar("TDTO")


class BaseLDAPSchemaFastAPIAdapter(
    BaseAdapter[TService],
    ABC,
    Generic[
        TService,
        TSchema,
        TPaginationSchema,
        TRequestSchema,
        TUpdateSchema,
        TDTO,
    ],
):
    """Base interface for LDAP Schema adapters with generic type support.

    This interface provides common functionality for LDAP schema adapters
    including automatic conversion between schemas and DTOs using adaptix.
    """

    def __init__(self, service: TService) -> None:
        """Initialize the adapter with service and converters.

        :param TService service: The service instance to use.
        """
        super().__init__(service)
        self._converter = self._get_converter()

    @abstractmethod
    def _get_converter(self) -> tuple[Callable, Callable]:
        """Get the converter functions for schema <-> DTO conversion.

        Should return a dictionary with keys:
        - 'schema_to_dto': function to convert schema to DTO
        - 'dto_to_schema': function to convert DTO to schema

        :return dict[str, Callable]: Dictionary of converter functions.
        """

    def _convert_schema_to_dto(self, schema: TSchema) -> Any:
        """Convert schema to DTO using adaptix converter.

        :param TSchema schema: Schema instance to convert.
        :return Any: Converted DTO instance.
        """
        if not self._converter:
            raise NotImplementedError(
                "No converter available for this adapter",
            )
        return self._converter[0](schema)

    def _convert_dto_to_schema(self, dto: TDTO) -> Any:
        """Convert DTO to schema using adaptix converter.

        :param TDTO dto: DTO instance to convert.
        :return Any: Converted schema instance.
        """
        if not self._converter:
            raise NotImplementedError(
                "No converter available for this adapter",
            )
        return self._converter[1](dto)

    @abstractmethod
    async def create(
        self,
        request_data: TRequestSchema,
    ) -> None:
        """Create a new entity.

        :param TRequestSchema request_data: Data for creating entity.
        :return None.
        """

    @abstractmethod
    async def get(
        self,
        name: str,
    ) -> TSchema:
        """Get a single entity by name.

        :param str name: Name of the entity.
        :return TSchema: Entity schema.
        """

    @abstractmethod
    async def get_list_paginated(
        self,
        params: PaginationParams,
    ) -> TPaginationSchema:
        """Get a list of entities with pagination.

        :param PaginationParams params: Pagination parameters.
        :return TPaginationSchema: Paginated result schema.
        """

    @abstractmethod
    async def update(
        self,
        name: str,
        request_data: TUpdateSchema,
    ) -> None:
        """Modify an entity.

        :param str name: Name of the entity to modify.
        :param TUpdateSchema request_data: Updated data.
        :return None.
        """

    @abstractmethod
    async def delete_bulk(
        self,
        names: LimitedListType,
    ) -> None:
        """Delete multiple entities.

        :param LimitedListType names: Names of entities to delete.
        :return None.
        """


def create_adaptix_converter(
    schema_class: type,
    dto_class: type,
) -> tuple[Callable, Callable]:
    """Create adaptix converter functions for schema <-> DTO conversion.

    :param type schema_class: Schema class type.
    :param type dto_class: DTO class type.
    :return dict[str, Callable]: Dictionary with converter functions.
    """
    has_id_field = (
        hasattr(dto_class, "__annotations__")
        and "id" in dto_class.__annotations__
    )

    if has_id_field:
        schema_to_dto_recipe = [allow_unlinked_optional(P[dto_class].id)]
        dto_to_schema_recipe = [
            link_function(lambda x: x.id or 0, P[schema_class].id),
        ]

        return (
            get_converter(
                schema_class,
                dto_class,
                recipe=schema_to_dto_recipe,
            ),
            get_converter(
                dto_class,
                schema_class,
                recipe=dto_to_schema_recipe,
            ),
        )
    else:
        return (
            get_converter(schema_class, dto_class),
            get_converter(dto_class, schema_class),
        )
