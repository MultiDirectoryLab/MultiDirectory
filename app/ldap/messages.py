"""Base LDAP message builder."""

from collections import defaultdict
from pprint import pprint

from asn1 import Decoder, Numbers
from pydantic import BaseModel, Field

from .asn1parser import ASN1Row, parse_asn1_to_dict
from .ldap_requests import BaseRequest, message_id_map


class LDAPMessage(BaseModel):
    """Base message structure. Pydantic for types validation."""

    message_id: int = Field(..., alias='messageID')
    protocol_op: int = Field(..., alias='protocolOP')
    context: BaseRequest = Field(...)

    @classmethod
    def from_bytes(cls, source: bytes):
        """Create message from bytes."""
        decoder = Decoder()
        decoder.start(source)
        output: dict[str, list[ASN1Row]] = defaultdict(list)
        parse_asn1_to_dict(decoder, output)

        pprint(output)
        sequence = output['field-0'][0]

        if sequence.tag_id.value != Numbers.Sequence:
            raise ValueError('Wrong schema')

        message, protocol = output[sequence.value]
        context = message_id_map[protocol.tag_id.value]()  # TODO: pass data

        return cls(
            messageID=message.value,
            protocolOP=protocol.tag_id.value,
            context=context,
        )
