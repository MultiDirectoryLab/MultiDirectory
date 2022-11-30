"""Base LDAP message builder."""

from abc import ABC

from asn1 import Classes, Encoder, Numbers
from pydantic import BaseModel, Field

from .asn1parser import asn1todict
from .dialogue import Session
from .ldap_requests import BaseRequest, protocol_id_map
from .ldap_responses import BaseResponse


class LDAPMessage(ABC, BaseModel):
    """Base message structure. Pydantic for types validation."""

    message_id: int = Field(..., alias='messageID')
    protocol_op: int = Field(..., alias='protocolOP')
    context: BaseRequest | BaseResponse = Field()


class LDAPResponseMessage(LDAPMessage):
    """Response message."""

    context: BaseResponse

    def encode(self) -> bytes:
        """Encode message to asn1."""
        enc = Encoder()
        enc.start()
        enc.enter(Numbers.Sequence, cls=Numbers.Enumerated)
        enc.write(self.message_id, Numbers.Integer)
        enc.enter(nr=self.context.PROTOCOL_OP, cls=Classes.Application)
        self.context.to_asn1(enc)
        enc.leave()
        enc.leave()
        return enc.output()


class LDAPRequestMessage(LDAPMessage):
    """Request message interface."""

    context: BaseRequest

    @classmethod
    def from_bytes(cls, source: bytes):
        """Create message from bytes."""
        output = asn1todict(source)
        sequence = output.pop('field-0')[0]

        if sequence.tag_id.value != Numbers.Sequence:
            raise ValueError('Wrong schema')

        message_id, protocol = output[sequence.value]
        context = protocol_id_map[protocol.tag_id.value].from_data(output)
        return cls(
            messageID=message_id.value,
            protocolOP=protocol.tag_id.value,
            context=context,
        )

    async def handle(self, session: Session) -> LDAPResponseMessage:
        """Call unique context handler."""
        response = await self.context.handle(session)
        return LDAPResponseMessage(
            messageID=self.message_id,
            protocolOP=response.PROTOCOL_OP,
            context=response,
        )
