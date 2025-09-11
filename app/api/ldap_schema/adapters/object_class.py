"""Object Class FastAPI Adapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import P
from adaptix.conversion import get_converter, link_function
from fastapi import status

from api.base_adapter import BaseAdapter
from api.ldap_schema.adapters.base_ldap_schema_adapter import BaseLDAPSchema
from api.ldap_schema.schema import (
    ObjectClassPaginationSchema,
    ObjectClassRequestSchema,
    ObjectClassSchema,
    ObjectClassUpdateSchema,
)
from ldap_protocol.ldap_schema.constants import DEFAULT_OBJECT_CLASS_IS_SYSTEM
from ldap_protocol.ldap_schema.dto import (
    ObjectClassDTO,
    ObjectClassRequestDTO,
    ObjectClassUpdateDTO,
)
from ldap_protocol.ldap_schema.exceptions import (
    ObjectClassAlreadyExistsError,
    ObjectClassCantModifyError,
    ObjectClassNotFoundError,
)
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO


def make_object_class_request_dto(
    request: ObjectClassRequestSchema,
) -> ObjectClassRequestDTO:
    """Convert ObjectClassRequestSchema to ObjectClassRequestDTO."""
    return ObjectClassRequestDTO(
        oid=request.oid,
        name=request.name,
        superior_name=request.superior_name,
        kind=request.kind,
        is_system=DEFAULT_OBJECT_CLASS_IS_SYSTEM,
        attribute_type_names_must=request.attribute_type_names_must,
        attribute_type_names_may=request.attribute_type_names_may,
    )


def make_object_class_schema(dto: ObjectClassDTO) -> ObjectClassSchema:
    """Convert ObjectClassDTO to ObjectClassSchema."""
    return ObjectClassSchema(
        oid=dto.oid,
        name=dto.name,
        superior_name=dto.superior_name,
        kind=dto.kind,
        is_system=dto.is_system,
        attribute_type_names_must=[
            attr.name for attr in dto.attribute_types_must
        ],
        attribute_type_names_may=[
            attr.name for attr in dto.attribute_types_may
        ],
    )


def make_object_class_update_dto(
    request: ObjectClassUpdateSchema,
) -> ObjectClassUpdateDTO:
    """Convert ObjectClassUpdateSchema to ObjectClassUpdateDTO."""
    return ObjectClassUpdateDTO(
        attribute_type_names_must=request.attribute_type_names_must,
        attribute_type_names_may=request.attribute_type_names_may,
    )


_convert_request_to_dto = get_converter(
    ObjectClassRequestSchema,
    ObjectClassRequestDTO,
    recipe=[
        link_function(
            lambda _: DEFAULT_OBJECT_CLASS_IS_SYSTEM,
            P[ObjectClassRequestDTO].is_system,
        ),
    ],
)

_convert_dto_to_schema = get_converter(
    ObjectClassDTO,
    ObjectClassSchema,
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

_convert_update_to_dto = get_converter(
    ObjectClassUpdateSchema,
    ObjectClassUpdateDTO,
)


class ObjectClassFastAPIAdapter(
    BaseAdapter[ObjectClassDAO],
    BaseLDAPSchema,
):
    """Object Class FastAPI Adapter."""

    _schema = ObjectClassSchema
    _pagination_schema = ObjectClassPaginationSchema
    _request_schema = ObjectClassRequestSchema
    _update_schema = ObjectClassUpdateSchema
    _dto = ObjectClassDTO
    converter_to_dto = _convert_request_to_dto
    converter_to_schema = _convert_dto_to_schema

    _exceptions_map: dict[type[Exception], int] = {
        ObjectClassAlreadyExistsError: status.HTTP_409_CONFLICT,
        ObjectClassNotFoundError: status.HTTP_404_NOT_FOUND,
        ObjectClassCantModifyError: status.HTTP_403_FORBIDDEN,
    }

    async def create(self, request_data: ObjectClassRequestSchema) -> None:
        """Create a new Object Class."""
        dto = self._convert_schema_to_dto(request_data)
        await self._service.create_one(dto)

    async def update(
        self,
        name: str,
        request_data: ObjectClassUpdateSchema,
    ) -> None:
        """Modify an Object Class."""
        object_class = await self._service.get_one_by_name(name)
        update_dto = _convert_update_to_dto(request_data)
        await self._service.modify_one(object_class, update_dto)
