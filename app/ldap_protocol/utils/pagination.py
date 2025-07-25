"""Pagination util.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

import sys
from dataclasses import dataclass
from math import ceil
from typing import Sequence, TypeVar

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.sql.expression import Select

from models import Base

P = TypeVar("P", contravariant=True, bound=BaseModel)
S = TypeVar("S", contravariant=True, bound=Base)


class PaginationParams(BaseModel):
    """Pagination parameters."""

    page_number: int = Field(
        ...,
        ge=1,
        le=sys.maxsize,
    )
    page_size: int = Field(
        default=25,
        ge=1,
        le=100,
    )
    query: str | None = None


def build_paginated_search_query[S: Base](
    model: type[S],
    order_by_field: InstrumentedAttribute,
    params: PaginationParams,
    search_field: InstrumentedAttribute | None = None,
) -> Select[tuple[S]]:
    """Build query."""
    query = select(model).order_by(order_by_field)

    if params.query:
        if search_field is None:
            search_field = order_by_field

        query = query.where(search_field.ilike(f"%{params.query}%"))

    return query


@dataclass
class PaginationMetadata:
    """Pagination metadata."""

    page_number: int
    page_size: int
    total_count: int | None = None
    total_pages: int | None = None


class BasePaginationSchema[P: BaseModel](BaseModel):
    """Paginator Schema."""

    metadata: PaginationMetadata
    items: list[P]

    class Config:
        """Config for Paginator."""

        arbitrary_types_allowed = True


@dataclass
class PaginationResult[S: Base]:
    """Paginator.

    Paginator contains metadata about pagination and chunk of items.
    """

    metadata: PaginationMetadata
    items: Sequence[S]

    @classmethod
    async def get(
        cls,
        query: Select[tuple[S]],
        params: PaginationParams,
        session: AsyncSession,
    ) -> "PaginationResult[S]":
        """Get paginator."""
        if query._order_by_clause is None or len(query._order_by_clause) == 0:  # noqa SLF001
            raise ValueError("Select query must have an order_by clause.")

        metadata = PaginationMetadata(
            page_number=params.page_number,
            page_size=params.page_size,
        )

        total_count_query = select(func.count()).select_from(query.subquery())
        metadata.total_count = (await session.scalars(total_count_query)).one()
        metadata.total_pages = ceil(metadata.total_count / params.page_size)

        offset = (params.page_number - 1) * params.page_size
        query = query.offset(offset).limit(params.page_size)
        result = await session.scalars(query)
        items = result.all()

        return cls(metadata=metadata, items=items)
