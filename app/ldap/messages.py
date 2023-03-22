"""Base LDAP message builder."""

from abc import ABC
from typing import AsyncGenerator

from asn1 import Classes, Decoder, Encoder, Numbers
from pydantic import BaseModel, Field

from .asn1parser import asn1todict
from .dialogue import LDAPCodes, Session
from .ldap_requests import BaseRequest, protocol_id_map
from .ldap_responses import BaseResponse, LDAPResult


class Control(BaseModel):
    """Controls class."""

    control_type: str
    criticality: bool = False
    control_value: str = ''


class LDAPMessage(ABC, BaseModel):
    """Base message structure. Pydantic for types validation."""

    message_id: int = Field(..., alias='messageID')
    protocol_op: int = Field(..., alias='protocolOP')
    context: BaseRequest | BaseResponse = Field()
    controls: list[Control] = []


class LDAPResponseMessage(LDAPMessage):
    """Response message."""

    context: BaseResponse

    def encode(self) -> bytes:
        """Encode message to asn1."""
        enc = Encoder()
        enc.start()
        enc.enter(Numbers.Sequence)
        enc.write(self.message_id, Numbers.Integer)
        enc.enter(nr=self.context.PROTOCOL_OP, cls=Classes.Application)
        self.context.to_asn1(enc)
        enc.leave()

        if self.controls:
            enc.enter(Numbers.Sequence)
            for control in self.controls:
                enc.enter(Numbers.Sequence)
                enc.write(control.control_type, Numbers.OctetString)
                enc.write(control.criticality, Numbers.Boolean)
                enc.write(control.control_value, Numbers.OctetString)
                enc.leave()
            enc.leave()

        enc.leave()
        return enc.output()


class LDAPRequestMessage(LDAPMessage):
    """Request message interface."""

    context: BaseRequest

    @classmethod
    def from_bytes(cls, source: bytes):
        """Create message from bytes."""
        dec = Decoder()
        dec.start(source)
        output = asn1todict(dec)

        sequence = output[0]
        if sequence.tag_id.value != Numbers.Sequence:
            raise ValueError('Wrong schema')

        seq_fields = sequence.value
        message_id, protocol = seq_fields[:2]

        controls = []

        try:
            for ctrl in seq_fields[2].value:
                controls.append(Control(
                    control_type=ctrl[0].value,
                    criticality=ctrl[1].value,
                    control_value=ctrl[2].value,
                ))
        except IndexError:
            pass

        from loguru import logger
        logger.debug({"len": len(seq_fields), "content": seq_fields})

        context = protocol_id_map[
            protocol.tag_id.value].from_data(protocol.value)
        return cls(
            messageID=message_id.value,
            protocolOP=protocol.tag_id.value,
            context=context,
            controls=controls,
        )

    @classmethod
    def from_err(cls, source: bytes, err: Exception) -> LDAPResponseMessage:
        """Create error response message.

        :param bytes source: source data
        :param Exception err: any error
        :raises ValueError: on invalid schema
        :return LDAPResponseMessage: response with err code
        """
        output = asn1todict(source)
        message_id = 0
        protocol_op = -1

        try:
            sequence = output[0]
            seq_fields = sequence.value
            message, protocol = seq_fields[:2]
            protocol_op = protocol.tag_id.value
            message_id = message.value
        except (KeyError, ValueError, IndexError):
            pass

        return LDAPResponseMessage(
            messageID=message_id,
            protocolOP=protocol_op,
            context=LDAPResult(
                resultCode=LDAPCodes.PROTOCOL_ERROR,
                matchedDN='',
                errorMessage=str(err)),
        )

    async def create_response(self, session: Session) -> \
            AsyncGenerator[LDAPResponseMessage, None]:
        """Call unique context handler.

        :yield LDAPResponseMessage: create response for context.
        """
        async for response in self.context.handle(session):
            yield LDAPResponseMessage(
                messageID=self.message_id,
                protocolOP=response.PROTOCOL_OP,
                context=response,
                controls=self.controls,
            )
