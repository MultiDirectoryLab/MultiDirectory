"""Subcontainers for requests/responses."""

from enum import Enum


class Scope(int, Enum):
    """Enum for search request."""

    BASE_OBJECT = 0
    SINGLEL_EVEL = 1
    WHOLE_SUBTREE = 2
    SUBORDINATE_SUBTREE = 3


class DerefAliases(int, Enum):
    """Enum for search request."""

    NEVER_DEREF_ALIASES = 0
    DEREF_IN_SEARCHING = 1
    DEREF_FINDING_BASE_OBJ = 2
    DEREF_ALWAYS = 3
