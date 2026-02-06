"""Custom SQLAlchemy types for PostgreSQL.

This module defines custom type decorators for SQLAlchemy that handle
automatic conversion between Python types and PostgreSQL column types.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import Dialect, LargeBinary, TypeDecorator

from enums import AuthorizationRules


class AuthorizationRulesType(TypeDecorator):
    """Custom type for API permissions array."""

    impl = LargeBinary
    cache_ok = True

    def process_bind_param(
        self,
        value: AuthorizationRules | int | None,
        dialect: Dialect,  # noqa: ARG002
    ) -> None | bytes:
        """Convert strings to AuthorizationRules enums when loading from DB."""
        if value is None:
            return None

        raw = (
            value.value
            if isinstance(value, AuthorizationRules)
            else int(value)
        )

        if raw == 0:
            return b"\x00"
        length = (raw.bit_length() + 7) // 8
        return raw.to_bytes(length, byteorder="little")

    def process_result_value(
        self,
        value: None | bytes,
        dialect: Dialect,  # noqa: ARG002
    ) -> None | AuthorizationRules:
        """Convert enums to strings when saving to DB."""
        if not value:
            return None
        decoded = int.from_bytes(value, byteorder="little")
        return AuthorizationRules(decoded)
