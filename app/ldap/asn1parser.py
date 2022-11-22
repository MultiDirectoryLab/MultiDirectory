"""ASN1 parser and decoder wrapper with dataclasses."""

from dataclasses import dataclass
from typing import Any

from asn1 import Classes, Decoder, Numbers, Tag, Types


@dataclass
class ASN1id:
    """ASN1 metadata."""

    string: str
    value: Any

    def __str__(self):  # noqa: D105
        return self.string

    def __repr__(self):  # noqa: D105
        return f'[{self.string}: {repr(self.value)}]'


@dataclass
class ASN1Row:
    """Row with metadata."""

    class_id: ASN1id
    tag_id: ASN1id
    value: Any

    @classmethod
    def from_tag(cls, tag: Tag, value: Any) -> 'ASN1Row':
        """Create row from tag."""
        return cls(
            ASN1id(class_id_to_string(tag.cls), tag.cls),
            ASN1id(tag_id_to_string(tag.nr), tag.nr),
            value,
        )


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
    Classes.Universal: "U",
    Classes.Application: "A",
    Classes.Context: "C",
    Classes.Private: "P",
}


def value_to_string(tag, value):
    """Convert value to string."""
    if tag.nr == Numbers.Integer:
        return int(value)
    if isinstance(value, (bytes, str)):
        return value
    return repr(value)


def tag_id_to_string(identifier):
    """Return a string representation of a ASN.1 id."""
    return tag_id_to_string_map.get(identifier, '{:#02x}'.format(identifier))


def class_id_to_string(identifier):
    """Return a string representation of an ASN.1 class."""
    if identifier in class_id_to_string_map:
        return class_id_to_string_map[identifier]
    raise ValueError('Illegal class: {:#02x}'.format(identifier))


def parse_asn1_to_dict(
    decoder: Decoder,
    output: dict,
    depth: int = 0,
    trace: bool = True,
):
    """Collect ASN.1 data to dict."""
    while not decoder.eof():
        tag = decoder.peek()
        filed_name = f'field-{depth}'

        if tag.typ == Types.Primitive:
            tag, value = decoder.read()
            field = ASN1Row.from_tag(tag, value_to_string(tag, value))
            output[filed_name].append(field)

            if trace:
                print(
                    ' ' * 4 * depth,
                    f"[{field.class_id}] {field.tag_id}: {field.value}")

        elif tag.typ == Types.Constructed:
            new_depth = depth + 1

            decoder.enter()
            parse_asn1_to_dict(decoder, output, new_depth, trace)
            decoder.leave()

            field = ASN1Row.from_tag(tag, f'field-{new_depth}')
            output[filed_name].append(field)

            if trace:
                print(' ' * 4 * depth, f"[{field.class_id}] {field.tag_id}")
