"""Subcontainers for requests/responses."""

from enum import Enum


class Scope(int, Enum):
    base_object = 0
    singlel_evel = 1
    whole_subtree = 2
    subordinate_subtree = 3


class DerefAliases(int, Enum):
    never_deref_aliases = 0
    deref_in_searching = 1
    deref_finding_base_obj = 2
    deref_always = 3
