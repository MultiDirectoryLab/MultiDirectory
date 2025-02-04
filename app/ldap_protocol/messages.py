"""Base LDAP message builder.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC
from typing import AsyncGenerator, Callable

from asn1 import Classes, Decoder, Encoder, Numbers
from loguru import logger
from pydantic import BaseModel, Field, SerializeAsAny

from .asn1parser import ASN1Row, asn1todict
from .ldap_codes import LDAPCodes
from .ldap_requests import BaseRequest, protocol_id_map
from .ldap_responses import BaseResponse, LDAPResult
from .utils.helpers import get_class_name


class Control(BaseModel):
    """Controls class."""

    control_type: str
    criticality: bool = False
    control_value: str = ""


class LDAPMessage(ABC, BaseModel):
    """Base message structure. Pydantic for types validation."""

    message_id: int = Field(..., alias="messageID")
    protocol_op: int = Field(..., alias="protocolOP")
    context: BaseRequest | BaseResponse
    controls: list[Control] = []

    @property
    def name(self) -> str:
        """Message name."""
        return get_class_name(self.context)


class LDAPResponseMessage(LDAPMessage):
    """Response message."""

    context: SerializeAsAny[BaseResponse]

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

    context: SerializeAsAny[BaseRequest]

    @classmethod
    def from_bytes(cls, source: bytes) -> "LDAPRequestMessage":
        """Create message from bytes."""
        dec = Decoder()
        dec.start(source)
        output = asn1todict(dec)

        sequence = output[0]
        if sequence.tag_id != Numbers.Sequence:
            raise ValueError("Wrong schema")

        seq_fields: list[ASN1Row] = sequence.value
        message_id: ASN1Row = seq_fields[0]
        protocol: ASN1Row = seq_fields[1]

        controls = []

        try:
            for ctrl in seq_fields[2].value:
                controls.append(
                    Control(
                        control_type=ctrl.value[0].value,
                        criticality=ctrl.value[1].value,
                        control_value=ctrl.value[2].value,
                    ),
                )
        except (IndexError, ValueError, AttributeError):
            pass

        if len(seq_fields) >= 3:
            logger.debug({"controls": seq_fields[2]})

        context = protocol_id_map[protocol.tag_id].from_data(protocol.value)
        return cls(
            messageID=message_id.value,
            protocolOP=protocol.tag_id,
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
            message: ASN1Row = seq_fields[0]
            protocol: ASN1Row = seq_fields[1]
            protocol_op = protocol.tag_id
            message_id = message.value
        except (KeyError, ValueError, IndexError):
            pass

        return LDAPResponseMessage(
            messageID=message_id,
            protocolOP=protocol_op,
            context=LDAPResult(
                result_code=LDAPCodes.PROTOCOL_ERROR,
                matchedDN="",
                errorMessage=str(err),
            ),
        )

    async def create_response(
        self,
        handler: Callable[..., AsyncGenerator[BaseResponse, None]],
    ) -> AsyncGenerator[LDAPResponseMessage, None]:
        """Call unique context handler.

        :yield LDAPResponseMessage: create response for context.
        """
        async for response in handler():
            yield LDAPResponseMessage(
                messageID=self.message_id,
                protocolOP=response.PROTOCOL_OP,
                context=response,
                controls=self.controls,
            )
