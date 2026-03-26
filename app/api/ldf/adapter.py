"""LDF version adapter."""

from api.base_adapter import BaseAdapter
from api.ldf.schema import LdfVersionPaginationSchema, LdfVersionSchema
from ldap_protocol.ldf.dto import LdfVersionDTO
from ldap_protocol.ldf.ldf_use_case import LdfVersionUseCase
from ldap_protocol.utils.pagination import PaginationParams


def _convert_dto_to_schema(dto: LdfVersionDTO) -> LdfVersionSchema:
    return LdfVersionSchema(
        version=dto.version,
        d_create=dto.d_create,
        status=dto.status,
    )


class LdfVersionFastAPIAdapter(BaseAdapter[LdfVersionUseCase]):
    """Adapter for LDF version handling."""

    async def get_list_paginated(
        self,
        params: PaginationParams,
    ) -> LdfVersionPaginationSchema:
        """Get paginated LDF versions."""
        pagination = await self._service.get_paginator(params)
        items = [_convert_dto_to_schema(item) for item in pagination.items]
        return LdfVersionPaginationSchema(
            metadata=pagination.metadata,
            items=items,
        )
