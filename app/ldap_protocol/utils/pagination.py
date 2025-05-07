"""Pagination util.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE.
"""

import sys
from math import ceil
from typing import Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.expression import Select

from models import Base

T = TypeVar("T", contravariant=True, bound=Base)


class PaginationParams(BaseModel):
    """Модель для параметров пагинации."""

    page_number: int = Field(
        ...,
        ge=1,
        le=sys.maxsize,
        description="Page number.",
    )
    page_size: int = Field(
        ...,
        ge=1,
        le=100,
        description="Page size.",
    )


@runtime_checkable
class SchemaProtocol(Protocol[T]):
    """Protocol for Schema."""

    @classmethod
    def from_db(cls, sqla_object: T) -> "SchemaProtocol":
        """Create an instance from database."""


class PaginationResult[T: Base](BaseModel):
    """Paginator."""

    params: PaginationParams
    total_pages: int
    items: list[SchemaProtocol[T]]

    class Config:
        """Config for Paginator."""

        arbitrary_types_allowed = True

    @classmethod
    async def get(
        cls,
        query: Select,
        params: PaginationParams,
        sqla_model: type[Base],
        schema_model: type[SchemaProtocol[T]],
        session: AsyncSession,
    ) -> "PaginationResult":
        """Get paginator."""
        if query._order_by_clause is None or len(query._order_by_clause) == 0:
            raise ValueError("Select query must have an order_by clause.")

        total_count_query = select(func.count()).select_from(sqla_model)
        total_count = (await session.scalars(total_count_query)).one()
        total_pages = ceil(total_count / params.page_size)

        offset = (params.page_number - 1) * params.page_size
        query = query.offset(offset).limit(params.page_size)
        result = await session.scalars(query)

        return cls(
            params=params,
            total_pages=total_pages,
            items=[schema_model.from_db(item) for item in result.all()],
        )
