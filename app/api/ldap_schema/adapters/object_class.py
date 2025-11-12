"""Object Class FastAPI Adapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import P
from adaptix.conversion import get_converter, link_function
from fastapi import status

from api.base_adapter import BaseAdapter
from api.ldap_schema.adapters.base_ldap_schema_adapter import (
    BaseLDAPSchemaAdapter,
)
from api.ldap_schema.schema import (
    ObjectClassPaginationSchema,
    ObjectClassSchema,
    ObjectClassUpdateSchema,
)
from enums import KindType
from ldap_protocol.ldap_schema.constants import DEFAULT_OBJECT_CLASS_IS_SYSTEM
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO, ObjectClassDTO
from ldap_protocol.ldap_schema.exceptions import (
    ObjectClassAlreadyExistsError,
    ObjectClassCantModifyError,
    ObjectClassNotFoundError,
)
from ldap_protocol.ldap_schema.object_class_use_case import ObjectClassUseCase
from ldap_protocol.permissions_checker import ApiPermissionError


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
    _converter_update_sch_to_dto = staticmethod(_convert_update_schema_to_dto)

    _exceptions_map: dict[type[Exception], int] = {
        ObjectClassAlreadyExistsError: status.HTTP_409_CONFLICT,
        ObjectClassNotFoundError: status.HTTP_404_NOT_FOUND,
        ObjectClassCantModifyError: status.HTTP_403_FORBIDDEN,
        ApiPermissionError: status.HTTP_403_FORBIDDEN,
    }
