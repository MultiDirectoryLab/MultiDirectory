"""Custom SQLAlchemy types for PostgreSQL.

This module defines custom type decorators for SQLAlchemy that handle
automatic conversion between Python types and PostgreSQL column types.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import Integer, TypeDecorator
from sqlalchemy.dialects.postgresql import ARRAY

from enums import ApiPermissionsType


class ApiPermissionsArray(TypeDecorator):
    """Custom type for API permissions array."""

    impl = ARRAY(Integer)
    cache_ok = True

    def process_result_value(self, value, dialect) -> list:  # type: ignore  # noqa: ARG002
        """Convert strings to ApiPermissionsType enums when loading from DB."""
        if value is None:
            return []
        return [ApiPermissionsType(int(v)) for v in value]

    def process_bind_param(self, value, dialect) -> list:  # type: ignore  # noqa: ARG002
        """Convert enums to strings when saving to DB."""
        if value is None:
            return []
        return [
            v.value if isinstance(v, ApiPermissionsType) else v for v in value
        ]
