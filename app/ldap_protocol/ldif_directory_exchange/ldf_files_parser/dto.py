"""DTOs for LDF file parser."""

from __future__ import annotations

import base64
from dataclasses import dataclass

from ldap_protocol.ldif_directory_exchange.ldf_files_parser.constants import (
    LdfAttributeOperations,
    LdfEntryChangeTypes,
)


@dataclass
class LdfAttribute:
    """Single LDF attribute with optional base64 decoding."""

    operation: LdfAttributeOperations
    name: str
    raw_value: str
    is_base64: bool
    decoded_value: str | None
    decoded_bytes: bytes | None

    @classmethod
    def from_raw(
        cls,
        operation: LdfAttributeOperations,
        name: str,
        raw_value: str,
        is_base64: bool,
    ) -> LdfAttribute:
        if not is_base64:
            return cls(
                operation=operation,
                name=name,
                raw_value=raw_value,
                is_base64=False,
                decoded_value=raw_value,
                decoded_bytes=None,
            )

        decoded_bytes = cls._decode_base64(raw_value)
        decoded_value = None
        if decoded_bytes is not None:
            try:
                decoded_value = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                decoded_value = None

        return cls(
            operation=operation,
            name=name,
            raw_value=raw_value,
            is_base64=True,
            decoded_value=decoded_value,
            decoded_bytes=decoded_bytes,
        )

    @staticmethod
    def _decode_base64(raw_value: str) -> bytes | None:
        try:
            return base64.b64decode(raw_value.encode("ascii"), validate=False)
        except Exception:
            raise


@dataclass
class LdfEntry:
    """Single LDF entry describing one object change."""

    dn: str | None
    change_type: LdfEntryChangeTypes | None
    ldf_attributes: list[LdfAttribute]


@dataclass
class LdfFileDTO:
    """Parsed LDF file content."""

    ldf_file_name: str
    ldf_file_path: str
    entries: list[LdfEntry]
