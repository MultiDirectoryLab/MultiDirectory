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

    def get_raw_definition(self) -> str:
        if not self.oid or not self.name or not self.syntax:
            raise ValueError(
                f"{self}: Fields 'oid', 'name', "
                "and 'syntax' are required for LDAP definition.",
            )
        chunks = [
            "(",
            self.oid,
            f"NAME '{self.name}'",
            f"SYNTAX '{self.syntax}'",
        ]
        if self.single_value:
            chunks.append("SINGLE-VALUE")
        if self.no_user_modification:
            chunks.append("NO-USER-MODIFICATION")
        chunks.append(")")
        return " ".join(chunks)


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

    def get_raw_definition(self) -> str:
        if not self.oid or not self.name or not self.kind:
            raise ValueError(
                f"{self}: Fields 'oid', 'name', and 'kind'"
                " are required for LDAP definition.",
            )
        chunks = ["(", self.oid, f"NAME '{self.name}'"]
        if self.superior_name:
            chunks.append(f"SUP {self.superior_name}")
        chunks.append(self.kind)
        if self.attribute_type_names_must:
            chunks.append(
                f"MUST ({' $ '.join(self.attribute_type_names_must)} )",
            )
        if self.attribute_type_names_may:
            chunks.append(
                f"MAY ({' $ '.join(self.attribute_type_names_may)} )",
            )
        chunks.append(")")
        return " ".join(chunks)

    @property
    def attribute_type_names_must(self) -> list[str]:
        return [a.name for a in self.attribute_types_must]

    @property
    def attribute_type_names_may(self) -> list[str]:
        return [a.name for a in self.attribute_types_may]
