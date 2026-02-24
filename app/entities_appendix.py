"""Deprecated entities."""

from __future__ import annotations

from dataclasses import dataclass, field

from enums import KindType


@dataclass
class AttributeType:
    """LDAP attribute type definition (schema element)."""

    id: int | None = field(init=False, default=None)
    oid: str = ""
    name: str = ""
    syntax: str = ""
    single_value: bool = False
    no_user_modification: bool = False
    is_system: bool = False
    system_flags: int = 0
    # NOTE: ms-adts/cf133d47-b358-4add-81d3-15ea1cff9cd9
    # see section 3.1.1.2.3 `searchFlags` (fANR) for details
    is_included_anr: bool = False


@dataclass
class ObjectClass:
    """LDAP object class definition with MUST/MAY attribute sets."""

    id: int = field(init=False)
    oid: str = ""
    name: str = ""
    superior_name: str | None = None
    kind: KindType | None = None
    is_system: bool = False
    superior: ObjectClass | None = field(default=None, repr=False)
    attribute_types_must: list[AttributeType] = field(
        default_factory=list,
        repr=False,
    )
    attribute_types_may: list[AttributeType] = field(
        default_factory=list,
        repr=False,
    )
