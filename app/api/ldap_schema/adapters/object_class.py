"""Object Class FastAPI Adapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Any

from fastapi import status

from api.ldap_schema import LimitedListType
from api.ldap_schema.adapters.base_ldap_schema_adapter import (
    BaseLDAPSchemaFastAPIAdapter,
)
from api.ldap_schema.schema import (
    ObjectClassPaginationSchema,
    ObjectClassRequestSchema,
    ObjectClassSchema,
    ObjectClassUpdateSchema,
)
from ldap_protocol.ldap_schema.constants import DEFAULT_OBJECT_CLASS_IS_SYSTEM
from ldap_protocol.ldap_schema.dto import ObjectClassDTO, ObjectClassUpdateDTO
from ldap_protocol.ldap_schema.exceptions import (
    ObjectClassAlreadyExistsError,
    ObjectClassCantModifyError,
    ObjectClassNotFoundError,
)
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams


class ObjectClassFastAPIAdapter(
    BaseLDAPSchemaFastAPIAdapter[
        ObjectClassDAO,
        ObjectClassSchema,
        ObjectClassPaginationSchema,
        ObjectClassRequestSchema,
        ObjectClassUpdateSchema,
        ObjectClassDTO,
    ],
):
    """Object Class FastAPI Adapter."""

    _exceptions_map: dict[type[Exception], int] = {
        ObjectClassAlreadyExistsError: status.HTTP_409_CONFLICT,
        ObjectClassNotFoundError: status.HTTP_404_NOT_FOUND,
        ObjectClassCantModifyError: status.HTTP_403_FORBIDDEN,
    }

    def _get_converter(self) -> dict[str, Any]:
        """Get converter functions for ObjectClass schema <-> DTO."""
        # ObjectClassSchema and ObjectClassDTO are incompatible for
        # automatic conversion due to different field structures
        # (names vs DTOs, id field, etc.)
        # Return empty dict to indicate no automatic conversion
        return {}

    async def create(
        self,
        request_data: ObjectClassRequestSchema,
    ) -> None:
        """Create a new Object Class."""
        await self._service.create_one(
            oid=request_data.oid,
            name=request_data.name,
            superior_name=request_data.superior_name,
            kind=request_data.kind,
            is_system=DEFAULT_OBJECT_CLASS_IS_SYSTEM,
            attribute_type_names_must=request_data.attribute_type_names_must,
            attribute_type_names_may=request_data.attribute_type_names_may,
        )

    async def get(self, name: str) -> ObjectClassSchema:
        """Get one Object Class."""
        object_class = await self._service.get_one_by_name(name)
        return ObjectClassSchema(
            oid=object_class.oid,
            name=object_class.name,
            superior_name=object_class.superior_name,
            kind=object_class.kind,
            is_system=object_class.is_system,
            attribute_type_names_must=[
                attr.name for attr in object_class.attribute_types_must
            ],
            attribute_type_names_may=[
                attr.name for attr in object_class.attribute_types_may
            ],
        )

    async def get_list_paginated(
        self,
        params: PaginationParams,
    ) -> ObjectClassPaginationSchema:
        """Get list of Object Classes with pagination."""
        pagination_result = await self._service.get_paginator(
            params=params,
        )

        items = [
            ObjectClassSchema(
                oid=item.oid,
                name=item.name,
                superior_name=item.superior_name,
                kind=item.kind,
                is_system=item.is_system,
                attribute_type_names_must=[
                    attr.name for attr in item.attribute_types_must
                ],
                attribute_type_names_may=[
                    attr.name for attr in item.attribute_types_may
                ],
            )
            for item in pagination_result.items
        ]
        return ObjectClassPaginationSchema(
            metadata=pagination_result.metadata,
            items=items,
        )

    async def update(
        self,
        name: str,
        request_data: ObjectClassUpdateSchema,
    ) -> None:
        """Modify an Object Class."""
        object_class = await self._service.get_one_by_name(name)
        await self._service.modify_one(
            object_class,
            ObjectClassUpdateDTO(
                attribute_type_names_must=request_data.attribute_type_names_must,
                attribute_type_names_may=request_data.attribute_type_names_may,
            ),
        )

    async def delete_bulk(self, names: LimitedListType) -> None:
        """Delete bulk Object Classes."""
        await self._service.delete_all_by_names(names)
