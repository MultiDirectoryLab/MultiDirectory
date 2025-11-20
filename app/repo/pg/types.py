"""Custom SQLAlchemy types for PostgreSQL.

This module defines custom type decorators for SQLAlchemy that handle
automatic conversion between Python types and PostgreSQL column types.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import String, TypeDecorator

from enums import AuthorizationRules


class ApiPermissionsType(TypeDecorator):
    """Custom type for API permissions array."""

    impl = String
    cache_ok = True

    def process_result_value(  # type: ignore
        self,
        value,
        dialect,  # noqa: ARG002
    ) -> AuthorizationRules | None:
        """Convert strings to AuthorizationRules enums when loading from DB."""
        if not value:
            return None
        return AuthorizationRules(int(value))

    def process_bind_param(self, value, dialect) -> str | None:  # type: ignore  # noqa: ARG002
        """Convert enums to strings when saving to DB."""
        if not value:
            return None
        return (
            str(value.value)
            if isinstance(value, AuthorizationRules)
            else str(value)
        )
