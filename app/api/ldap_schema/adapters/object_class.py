"""Object Class FastAPI Adapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import P
from adaptix.conversion import get_converter, link_function
from fastapi import status

from api.base_adapter import BaseAdapter
from api.ldap_schema import LimitedListType
from api.ldap_schema.adapters.base_ldap_schema_adapter import (
    BaseLDAPSchemaAdapter,
)
from api.ldap_schema.schema import (
    ObjectClassExtendedSchema,
    ObjectClassPaginationSchema,
    ObjectClassSchema,
    ObjectClassUpdateSchema,
)
from enums import KindType
from ldap_protocol.ldap_schema.constants import DEFAULT_OBJECT_CLASS_IS_SYSTEM
from ldap_protocol.ldap_schema.dto import (
    AttributeTypeDTO,
    ObjectClassDTO,
    ObjectClassExtendedDTO,
)
from ldap_protocol.ldap_schema.exceptions import (
    ObjectClassAlreadyExistsError,
    ObjectClassCantModifyError,
    ObjectClassNotFoundError,
)
from ldap_protocol.ldap_schema.object_class_use_case import ObjectClassUseCase
from ldap_protocol.utils.pagination import PaginationParams


def _convert_update_schema_to_dto(
    request: ObjectClassUpdateSchema,
) -> ObjectClassDTO[None, str]:
    """Convert ObjectClassUpdateSchema to ObjectClassDTO."""
    return ObjectClassDTO(
        oid="",
        name="",
        superior_name="",
        kind=KindType.STRUCTURAL,
        is_system=False,
        attribute_types_must=request.attribute_type_names_must,
        attribute_types_may=request.attribute_type_names_may,
    )


_convert_schema_to_dto = get_converter(
    ObjectClassSchema[None],
    ObjectClassDTO[None, str],
    recipe=[
        link_function(
            lambda _: DEFAULT_OBJECT_CLASS_IS_SYSTEM,
            P[ObjectClassDTO].is_system,
        ),
        link_function(lambda _: None, P[ObjectClassDTO].id),
        link_function(
            lambda x: x.attribute_type_names_must,
            P[ObjectClassDTO].attribute_types_must,
        ),
        link_function(
            lambda x: x.attribute_type_names_may,
            P[ObjectClassDTO].attribute_types_may,
        ),
    ],
)

_convert_dto_to_schema = get_converter(
    ObjectClassDTO[int, AttributeTypeDTO],
    ObjectClassSchema[int],
    recipe=[
        link_function(
            lambda dto: [attr.name for attr in dto.attribute_types_must],
            P[ObjectClassSchema].attribute_type_names_must,
        ),
        link_function(
            lambda dto: [attr.name for attr in dto.attribute_types_may],
            P[ObjectClassSchema].attribute_type_names_may,
        ),
    ],
)

_convert_dto_to_extended_schema = get_converter(
    ObjectClassExtendedDTO[AttributeTypeDTO],
    ObjectClassExtendedSchema,
    recipe=[
        link_function(
            lambda dto: [attr.name for attr in dto.attribute_types_must],
            P[ObjectClassExtendedSchema].attribute_type_names_must,
        ),
        link_function(
            lambda dto: [attr.name for attr in dto.attribute_types_may],
            P[ObjectClassExtendedSchema].attribute_type_names_may,
        ),
    ],
)


class ObjectClassFastAPIAdapter(
    BaseAdapter[ObjectClassUseCase],
    BaseLDAPSchemaAdapter[
        ObjectClassUseCase,
        ObjectClassSchema,
        ObjectClassUpdateSchema,
        ObjectClassPaginationSchema,
        ObjectClassDTO,
    ],
):
    """Object Class FastAPI Adapter."""

    _pagination_schema = ObjectClassPaginationSchema

    _converter_to_dto = staticmethod(_convert_schema_to_dto)
    _converter_to_schema = staticmethod(_convert_dto_to_schema)
    _converter_to_extended_schema = staticmethod(
        _convert_dto_to_extended_schema,
    )
    _converter_update_sch_to_dto = staticmethod(_convert_update_schema_to_dto)

    _exceptions_map: dict[type[Exception], int] = {
        ObjectClassAlreadyExistsError: status.HTTP_409_CONFLICT,
        ObjectClassNotFoundError: status.HTTP_404_NOT_FOUND,
        ObjectClassCantModifyError: status.HTTP_403_FORBIDDEN,
    }

    async def create(self, data: ObjectClassSchema) -> None:
        """Create a new entity."""
        dto = self._converter_to_dto(data)
        await self._service.create(dto)

    async def get(
        self,
        name: str,
    ) -> ObjectClassExtendedSchema:
        """Get a single entity by name."""
        object_class = await self._service.get(name)
        return self._converter_to_extended_schema(object_class)

    async def get_list_paginated(
        self,
        params: PaginationParams,
    ) -> ObjectClassPaginationSchema:
        """Get a list of entities with pagination."""
        pagination_result = await self._service.get_paginator(params)

        items: list[ObjectClassSchema] = [
            self._converter_to_schema(item) for item in pagination_result.items
        ]

        return self._pagination_schema(
            metadata=pagination_result.metadata,
            items=items,
        )

    async def update(
        self,
        name: str,
        data: ObjectClassUpdateSchema,
    ) -> None:
        """Modify an entity."""
        dto = self._converter_update_sch_to_dto(data)
        await self._service.update(name, dto)

    async def delete_bulk(
        self,
        names: LimitedListType,
    ) -> None:
        """Delete multiple entities."""
        await self._service.delete_all_by_names(names)
