"""LDF version router."""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Query

from api.ldifde import error_map, ldf_router
from api.ldifde.adapter import LdfVersionFastAPIAdapter
from api.ldifde.schema import LdfVersionPaginationSchema
from ldap_protocol.utils.pagination import PaginationParams


@ldf_router.get("/versions", error_map=error_map)
async def get_ldf_versions(
    adapter: FromDishka[LdfVersionFastAPIAdapter],
    params: Annotated[PaginationParams, Query()],
) -> LdfVersionPaginationSchema:
    """Get LDF versions with pagination."""
    return await adapter.get_list_paginated(params)
