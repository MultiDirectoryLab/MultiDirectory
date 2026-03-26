"""LDF version router."""

from typing import Annotated

from dishka.integrations.fastapi import FromDishka
from fastapi import Query

from api.ldf import error_map, ldf_router
from api.ldf.adapter import LdfVersionFastAPIAdapter
from api.ldf.schema import LdfVersionPaginationSchema
from ldap_protocol.utils.pagination import PaginationParams


@ldf_router.get("/versions", error_map=error_map)
async def get_ldf_versions(
    adapter: FromDishka[LdfVersionFastAPIAdapter],
    params: Annotated[PaginationParams, Query()],
) -> LdfVersionPaginationSchema:
    """Get LDF versions with pagination."""
    return await adapter.get_list_paginated(params)
