"""Subcontainers for requests/responses.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, StrEnum, unique
from typing import Annotated

import annotated_types
from pydantic import BaseModel, field_validator


class Scope(IntEnum):
    """Enum for search request."""

    BASE_OBJECT = 0
    SINGLE_LEVEL = 1
    WHOLE_SUBTREE = 2
    SUBORDINATE_SUBTREE = 3


class DerefAliases(IntEnum):
    """Enum for search request."""

    NEVER_DEREF_ALIASES = 0
    DEREF_IN_SEARCHING = 1
    DEREF_FINDING_BASE_OBJ = 2
    DEREF_ALWAYS = 3


class LDAPMatchingRule(StrEnum):
    """Enum for LDAP Matching Rules (extensibleMatch)."""

    LDAP_MATCHING_RULE_BIT_AND = "1.2.840.113556.1.4.803"
    LDAP_MATCHING_RULE_BIT_OR = "1.2.840.113556.1.4.804"
    LDAP_MATCHING_RULE_TRANSITIVE_EVAL = "1.2.840.113556.1.4.1941"
    LDAP_MATCHING_RULE_DN_WITH_DATA = "1.2.840.113556.1.4.2253"


class Operation(IntEnum):
    """Changes enum for modify request."""

    ADD = 0
    DELETE = 1
    REPLACE = 2


class PartialAttribute(BaseModel):
    """Partial attribite structure. Description in rfc2251 4.1.6."""

    type: Annotated[str, annotated_types.Len(max_length=8100)]
    vals: list[Annotated[str | bytes, annotated_types.Len(max_length=100000)]]

    @property
    def l_name(self) -> str:
        """Get lower case name."""
        return self.type.lower()

    @field_validator("type", mode="before")
    @classmethod
    def validate_type(cls, v: str | bytes | int) -> str:
        return str(v)

    @field_validator("vals", mode="before")
    @classmethod
    def validate_vals(cls, vals: list[str | int | bytes]) -> list[str | bytes]:
        return [v if isinstance(v, bytes) else str(v) for v in vals]

    class Config:
        """Allow class to use property."""

        arbitrary_types_allowed = True
        json_encoders = {
            bytes: lambda value: value.hex(),
        }


class Changes(BaseModel):
    """Changes for modify request."""

    operation: Operation
    modification: PartialAttribute

    def get_name(self) -> str:
        """Get mod name."""
        return self.modification.type.lower()


@unique
class ProtocolRequests(IntEnum):
    """Enum for LDAP requests."""

    BIND = 0
    UNBIND = 2
    SEARCH = 3
    MODIFY = 6
    ADD = 8
    DELETE = 10
    MODIFY_DN = 12
    COMPARE = 14
    ABANDON = 16
    EXTENDED = 23


@unique
class ProtocolResponse(IntEnum):
    """Enum for LDAP resposnes."""

    BIND = 1
    SEARCH_RESULT_ENTRY = 4
    SEARCH_RESULT_DONE = 5
    MODIFY = 7
    ADD = 9
    DELETE = 11
    MODIFY_DN = 13
    COMPARE = 15
    EXTENDED = 24
    INTERMEDIATE = 25
    SEARCH_RESULT_REFERENCE = 19


@unique
class OperationEvent(IntEnum):
    """Enum for operation events. Includes all LDAP requests."""

    BIND = ProtocolRequests.BIND
    UNBIND = ProtocolRequests.UNBIND
    SEARCH = ProtocolRequests.SEARCH
    MODIFY = ProtocolRequests.MODIFY
    ADD = ProtocolRequests.ADD
    DELETE = ProtocolRequests.DELETE
    MODIFY_DN = ProtocolRequests.MODIFY_DN
    COMPARE = ProtocolRequests.COMPARE
    ABANDON = ProtocolRequests.ABANDON
    EXTENDED = ProtocolRequests.EXTENDED
    CHANGE_PASSWORD = 40
    AFTER_2FA = 41
    KERBEROS_AUTH = 42
    CHANGE_PASSWORD_KERBEROS = 43
