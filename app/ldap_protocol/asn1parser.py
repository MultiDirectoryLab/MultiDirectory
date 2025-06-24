"""ASN1 parser and decoder wrapper with dataclasses.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from contextlib import suppress
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Generic, TypeVar

from asn1 import Classes, Decoder, Numbers, Tag, Types


class TagNumbers(IntEnum):
    """Enum for filter tags in LDAP search.

    ```
    AND = 0
    OR = 1
    NOT = 2
    EQUALITY_MATCH = 3
    SUBSTRING = 4
    GE = 5
    LE = 6
    PRESENT = 7
    APPROX_MATCH = 8
    EXTENSIBLE_MATCH = 9
    ```
    """

    AND = 0
    OR = 1
    NOT = 2
    EQUALITY_MATCH = 3
    SUBSTRING = 4
    GE = 5
    LE = 6
    PRESENT = 7
    APPROX_MATCH = 8
    EXTENSIBLE_MATCH = 9


class SubstringTag(IntEnum):
    """Enum for substring tags.

    ```
    INITIAL = 0
    ANY = 1
    FINAL = 2
    ```
    """

    INITIAL = 0
    ANY = 1
    FINAL = 2


T = TypeVar(
    "T",
    contravariant=True,
    bound="ASN1Row | list[ASN1Row] | str | bytes | int | float",
)


@dataclass
class ASN1Row(Generic[T]):
    """Row with metadata."""

    class_id: int
    tag_id: int
    value: T

    @classmethod
    def from_tag(cls, tag: Tag, value: T) -> "ASN1Row":
        """Create row from tag."""
        return cls(tag.cls, tag.nr, value)

    def _handle_extensible_match(self) -> str:
        """Handle extensible match filters."""
        oid = attribute = value = None
        dn_attributes = False

        if not isinstance(self.value, list):
            raise TypeError

        for child in self.value:
            tag_value = child.tag_id
            child_value = child.value

            if tag_value == 1:
                oid = child_value
            elif tag_value == 2:
                attribute = (
                    child_value.decode(errors="replace")
                    if isinstance(child_value, bytes)
                    else child_value
                )
            elif tag_value == 3:
                value = (
                    child_value.decode(errors="replace")
                    if isinstance(child_value, bytes)
                    else child_value
                )
            elif tag_value == 4:
                dn_attributes = bool(child_value)

        match = ""
        if attribute:
            match += attribute
        if oid:
            match += f":{oid}"
        if dn_attributes:
            match += ":dn"
        if value:
            match += f":={value}"
        else:
            match += ":=*"

        return f"({match})"

    def _handle_substring(self) -> str:
        """Process and format substring operations for LDAP."""
        value = (
            self.value.decode(errors="replace")
            if isinstance(self.value, bytes)
            else str(self.value)
        )
        substring_tag_map = {
            SubstringTag.INITIAL: f"{value}*",
            SubstringTag.ANY: f"*{value}*",
            SubstringTag.FINAL: f"*{value}",
        }
        try:
            substring_tag = SubstringTag(self.tag_id)
        except ValueError:
            raise ValueError(f"Invalid tag_id ({self.tag_id}) in substring")

        return substring_tag_map[substring_tag]

    def serialize(self, obj: "ASN1Row | T | None" = None) -> str:  # noqa: C901
        """Serialize an ASN.1 object or list into a string.

        Recursively processes ASN.1 structures to construct a valid LDAP
        filter string based on LDAP operations such as AND, OR, and
        substring matches.
        """
        if obj is None:
            obj = self

        if isinstance(obj, ASN1Row):
            value = obj.value
            operator = None

            if obj.class_id != Classes.Context:
                return self.serialize(value)

            if obj.tag_id in (
                TagNumbers.AND,
                TagNumbers.OR,
                TagNumbers.NOT,
            ):
                subfilters = "".join(self.serialize(v) for v in value)

                if obj.tag_id == TagNumbers.AND:
                    return f"(&{subfilters})"

                elif obj.tag_id == TagNumbers.OR:
                    return f"(|{subfilters})"
                else:
                    return f"(!{subfilters})"

            elif obj.tag_id == TagNumbers.PRESENT:
                return f"({self.serialize(value)}=*)"

            elif obj.tag_id == TagNumbers.EXTENSIBLE_MATCH:
                return obj._handle_extensible_match()

            else:
                operator_map: dict[int, str] = {
                    TagNumbers.EQUALITY_MATCH: "=",
                    TagNumbers.SUBSTRING: "*=",
                    TagNumbers.GE: ">=",
                    TagNumbers.LE: "<=",
                    TagNumbers.APPROX_MATCH: "~=",
                }
                operator = operator_map.get(obj.tag_id)

                if operator is None:
                    raise ValueError(
                        f"Invalid tag_id ({obj.tag_id}) in context"
                    )

            if isinstance(obj.value, list):
                if len(obj.value) == 2:
                    attr = self.serialize(value[0])
                    val = value[1]
                    if operator == "*=":
                        operator = "="
                        substrings = val.value[0]._handle_substring()
                        value_str = substrings
                    else:
                        value_str = self.serialize(val)

                    return f"({attr}{operator}{value_str})"

                return "".join(self.serialize(v) for v in obj.value)

            return self.serialize(obj.value)

        elif isinstance(obj, list):
            return "".join(self.serialize(v) for v in obj)

        elif isinstance(obj, bytes):
            return obj.decode(errors="replace")

        elif isinstance(obj, str):
            return obj

        elif isinstance(obj, int) or isinstance(obj, float):
            return str(obj)

        else:
            raise TypeError

    def to_ldap_filter(self) -> str:
        """Convert the ASN.1 object into an LDAP filter string.

        The method recursively serializes ASN.1 rows into the LDAP filter
        format based on tag IDs and class IDs.
        """
        return self.serialize()


def value_to_string(
    tag: Tag,
    value: str | bytes | int | bool,
) -> bytes | str | int:
    """Convert value to string."""
    if tag.nr == Numbers.Integer:
        with suppress(ValueError):
            return int(value)
        return value

    if isinstance(value, bytes):
        with suppress(UnicodeDecodeError):
            return value.decode().replace("\x00", "\\x00")
        return value

    if isinstance(value, str):
        return value

    return repr(value)


def asn1todict(decoder: Decoder) -> list[ASN1Row]:
    """Recursively collect ASN.1 data to list of ASNRows."""
    out = []
    while not decoder.eof():
        tag = decoder.peek()

        if tag.typ == Types.Primitive:
            tag, value = decoder.read()
            field = ASN1Row.from_tag(tag, value_to_string(tag, value))
            out.append(field)

        elif tag.typ == Types.Constructed:
            decoder.enter()
            new_out = asn1todict(decoder)
            decoder.leave()

            field = ASN1Row.from_tag(tag, new_out)
            out.append(field)

    return out


class LDAPOID(StrEnum):
    """Enum for LDAP OIDs."""

    PASSWORD_MODIFY = "1.3.6.1.4.1.4203.1.11.1"  # noqa
    WHOAMI = "1.3.6.1.4.1.4203.1.11.3"
    START_TLS = "1.3.6.1.4.1.1466.20037"
    PAGED_RESULTS = "1.2.840.113556.1.4.319"

    @classmethod
    def has_value(cls, value: str) -> bool:
        return value in cls._value2member_map_
