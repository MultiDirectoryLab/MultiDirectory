"""ASN1 parser and decoder wrapper with dataclasses.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from contextlib import suppress
from dataclasses import dataclass
from typing import Annotated, Any

from asn1 import Classes, Decoder, Encoder, Numbers, Tag, Types
from pydantic import AfterValidator


@dataclass
class ASN1id:
    """ASN1 metadata."""

    string: str
    value: Any

    def __str__(self) -> str:  # noqa: D105
        return self.string

    def __repr__(self) -> str:  # noqa: D105
        return f"[{self.string}: {repr(self.value)}]"


@dataclass
class ASN1Row:
    """Row with metadata."""

    class_id: ASN1id
    tag_id: ASN1id
    value: Any

    @classmethod
    def from_tag(cls, tag: Tag, value: Any) -> "ASN1Row":
        """Create row from tag."""
        return cls(
            ASN1id(class_id_to_string(tag.cls), tag.cls),
            ASN1id(tag_id_to_string(tag.nr), tag.nr),
            value,
        )

    def to_dict(self) -> dict:
        """Convert the object to string."""

        def serialize(obj: Any) -> dict | list | str:
            if isinstance(obj, ASN1Row):
                return {
                    "class_id": str(obj.class_id),
                    "tag_id": str(obj.tag_id),
                    "value": serialize(obj.value),
                }

            if isinstance(obj, list):
                return [serialize(item) for item in obj]

            return str(obj)

        return serialize(self)  # type: ignore


tag_id_to_string_map = {
    Numbers.Boolean: "BOOLEAN",
    Numbers.Integer: "INTEGER",
    Numbers.BitString: "BIT STRING",
    Numbers.OctetString: "OCTET STRING",
    Numbers.Null: "NULL",
    Numbers.ObjectIdentifier: "OBJECT",
    Numbers.PrintableString: "PRINTABLESTRING",
    Numbers.IA5String: "IA5STRING",
    Numbers.UTCTime: "UTCTIME",
    Numbers.GeneralizedTime: "GENERALIZED TIME",
    Numbers.Enumerated: "ENUMERATED",
    Numbers.Sequence: "SEQUENCE",
    Numbers.Set: "SET",
}

class_id_to_string_map = {
    Classes.Universal: "UNIVERSAL",
    Classes.Application: "APPLICATION",
    Classes.Context: "CONTEXT",
    Classes.Private: "PRIVATE",
}


def value_to_string(tag: Tag, value: Any) -> bytes | str | int:
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


def tag_id_to_string(identifier: int) -> Numbers:
    """Return a string representation of a ASN.1 id."""
    return tag_id_to_string_map.get(identifier, "{:#02x}".format(identifier))


def class_id_to_string(identifier: int) -> Classes:
    """Return a string representation of an ASN.1 class."""
    if identifier in class_id_to_string_map:
        return class_id_to_string_map[identifier]
    raise ValueError("Illegal class: {:#02x}".format(identifier))


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


def _validate_oid(oid: str) -> str:
    """Validate ldap oid with regex."""
    if not Encoder._re_oid.match(oid):
        raise ValueError("Invalid LDAPOID")
    return oid


LDAPOID = Annotated[str, AfterValidator(_validate_oid)]
