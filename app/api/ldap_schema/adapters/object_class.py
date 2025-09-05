"""Object Class FastAPI Adapter.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import status

from api.base_adapter import BaseAdapter
from api.ldap_schema import LimitedListType
from api.ldap_schema.schema import (
    ObjectClassPaginationSchema,
    ObjectClassRequestSchema,
    ObjectClassSchema,
    ObjectClassUpdateSchema,
)
from ldap_protocol.ldap_schema.dto import ObjectClassUpdateDTO
from ldap_protocol.ldap_schema.exceptions import (
    ObjectClassAlreadyExistsError,
    ObjectClassCantModifyError,
    ObjectClassNotFoundError,
)
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.utils.pagination import PaginationParams


class ObjectClassFastAPIAdapter(BaseAdapter[ObjectClassDAO]):
    """Object Class FastAPI Adapter."""

    _DEFAULT_OBJECT_CLASS_IS_SYSTEM = False

    _exceptions_map: dict[type[Exception], int] = {
        ObjectClassAlreadyExistsError: status.HTTP_409_CONFLICT,
        ObjectClassNotFoundError: status.HTTP_404_NOT_FOUND,
        ObjectClassCantModifyError: status.HTTP_403_FORBIDDEN,
    }

    def __init__(self, object_class_dao: ObjectClassDAO) -> None:
        """Initialize Object Class FastAPI Adapter."""
        self.object_class_dao = object_class_dao

    async def create_one_object_class(
        self,
        request_data: ObjectClassRequestSchema,
    ) -> None:
        """Create a new Object Class."""
        # await self.object_class_dao.create(
        #     ObjectClassRequestDTO(
        #         oid=request_data.oid,
        #         name=request_data.name,
        #         superior_name=request_data.superior_name,
        #         kind=request_data.kind,
        #         is_system=self._DEFAULT_OBJECT_CLASS_IS_SYSTEM,
        #         attribute_type_names_must=request_data.attribute_type_names_must,
        #         attribute_type_names_may=request_data.attribute_type_names_may,
        #     ),
        # )
        await self.object_class_dao.create_one(
            oid=request_data.oid,
            name=request_data.name,
            superior_name=request_data.superior_name,
            kind=request_data.kind,
            is_system=self._DEFAULT_OBJECT_CLASS_IS_SYSTEM,
            attribute_type_names_must=request_data.attribute_type_names_must,
            attribute_type_names_may=request_data.attribute_type_names_may,
        )

    async def get_one_object_class(
        self,
        object_class_name: str,
    ) -> ObjectClassSchema:
        """Get one Object Class."""
        object_class = await self.object_class_dao.get_one_by_name(
            object_class_name,
        )
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

    async def get_list_object_classes_with_pagination(
        self,
        params: PaginationParams,
    ) -> ObjectClassPaginationSchema:
        """Get list of Object Classes with pagination."""
        pagination_result = await self.object_class_dao.get_paginator(
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

    async def modify_one_object_class(
        self,
        object_class_name: str,
        request_data: ObjectClassUpdateSchema,
    ) -> None:
        """Modify an Object Class."""
        object_class = await self.object_class_dao.get_one_by_name(
            object_class_name,
        )
        await self.object_class_dao.modify_one(
            object_class,
            ObjectClassUpdateDTO(
                attribute_type_names_must=request_data.attribute_type_names_must,
                attribute_type_names_may=request_data.attribute_type_names_may,
            ),
        )

    async def delete_bulk_object_classes(
        self,
        object_classes_names: LimitedListType,
    ) -> None:
        """Delete bulk Object Classes."""
        await self.object_class_dao.delete_all_by_names(object_classes_names)
