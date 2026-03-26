"""LDF version API schemas."""

from datetime import datetime

from pydantic import BaseModel

from enums import LdfVersionStatus
from ldap_protocol.utils.pagination import BasePaginationSchema


class LdfVersionSchema(BaseModel):
    """LDF version response schema."""

    version: str
    d_create: datetime
    status: LdfVersionStatus | None = None


class LdfVersionPaginationSchema(
    BasePaginationSchema[LdfVersionSchema],
):
    """LDF version pagination schema."""

    items: list[LdfVersionSchema]
