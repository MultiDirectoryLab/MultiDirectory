"""LDF file operations constants."""

from enum import StrEnum


class LdfAttributeOperations(StrEnum):
    """LDF file operation."""

    REPLACE = "replace"
    ADD = "add"
    DELETE = "delete"


class LdfEntryChangeTypes(StrEnum):
    """LDF file change types."""

    NTDS_SCHEMA_DELETE = "ntdsSchemaDelete"
    NTDS_SCHEMA_MODIFY = "ntdsSchemaModify"
    NTDS_SCHEMA_ADD_UP = "ntdsSchemaAdd"
    NTDS_SCHEMA_ADD_LOW = "ntdsSchemaadd"
