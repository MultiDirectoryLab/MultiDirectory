"""Subcontainers for requests/responses.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, StrEnum

from pydantic import BaseModel

from ldap_protocol.ldap_responses import PartialAttribute


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


class Changes(BaseModel):
    """Changes for modify request."""

    operation: Operation
    modification: PartialAttribute

    def get_name(self) -> str:
        """Get mod name."""
        return self.modification.type.lower()


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
