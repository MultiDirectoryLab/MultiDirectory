"""LDAP response containers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from typing import Annotated, ClassVar

import annotated_types
from asn1 import Classes, Encoder, Numbers
from pydantic import AnyUrl, BaseModel, Field, SerializeAsAny, field_validator

from ldap_protocol.asn1parser import LDAPOID

from .ldap_codes import LDAPCodes

type_map = {
    bool: Numbers.Boolean,
    int: Numbers.Integer,
    bytes: Numbers.BitString,
    str: Numbers.OctetString,
    None: Numbers.Null,
    LDAPCodes: Numbers.Enumerated,
    LDAPOID: Numbers.OctetString,
}


class LDAPResult(BaseModel):
    """Base LDAP result structure."""

    result_code: LDAPCodes = Field(..., alias="resultCode")
    matched_dn: str = Field("", alias="matchedDN")
    error_message: str = Field("", alias="errorMessage")

    class Config:
        """Allow class to use property."""

        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            bytes: lambda value: value.hex(),
        }


class BaseEncoder(BaseModel):
    """Class with encoder methods."""

    def _get_asn1_fields(self) -> dict:
        fields = self.model_dump()
        fields.pop("PROTOCOL_OP", None)
        return fields

    def to_asn1(self, enc: Encoder) -> None:
        """Serialize flat structure to bytes, write to encoder buffer."""
        for value in self._get_asn1_fields().values():
            enc.write(value, type_map[type(value)])


class BaseResponse(ABC, BaseEncoder):
    """Base class for Response."""

    @property
    @abstractmethod
    def PROTOCOL_OP(self) -> int:  # noqa: N802
        """Protocol OP response code."""


class BindResponse(LDAPResult, BaseResponse):
    """Bind response. Description in rfc4511 4.2.2.

    BindResponse ::= [APPLICATION 1] SEQUENCE {
        COMPONENTS OF LDAPResult,
        serverSaslCreds    [7] OCTET STRING OPTIONAL }
    """

    PROTOCOL_OP: ClassVar[int] = 1
    server_sasl_creds: bytes | None = Field(None, alias="serverSaslCreds")

    def to_asn1(self, enc: Encoder) -> None:
        """Serialize flat structure to bytes, write to encoder buffer."""
        enc.write(self.result_code, type_map[type(self.result_code)])
        enc.write(self.matched_dn, type_map[type(self.matched_dn)])
        enc.write(self.error_message, type_map[type(self.error_message)])

        if self.server_sasl_creds:
            enc.write(
                self.server_sasl_creds,
                cls=Classes.Context,
                nr=7,
            )


class PartialAttribute(BaseModel):
    """Partial attribite structure. Description in rfc2251 4.1.6."""

    type: Annotated[str, annotated_types.Len(max_length=8100)]
    vals: list[Annotated[str | bytes, annotated_types.Len(max_length=100000)]]

    @field_validator("type", mode="before")
    @classmethod
    def validate_type(cls, v: str | bytes | int) -> str:
        return str(v)

    @field_validator("vals", mode="before")
    @classmethod
    def validate_vals(cls, vals: list[str | int | bytes]) -> list[str | bytes]:
        return [v if isinstance(v, bytes) else str(v) for v in vals]

    class Config:
        """Allow class to use property."""

        arbitrary_types_allowed = True
        json_encoders = {
            bytes: lambda value: value.hex(),
        }


class SearchResultEntry(BaseResponse):
    """Search Response.

    SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
            objectName      LDAPDN,
            attributes      PartialAttributeList }

    PartialAttributeList ::= SEQUENCE OF
                            partialAttribute PartialAttribute

    SearchResultReference ::= [APPLICATION 19] SEQUENCE
                                SIZE (1..MAX) OF uri URI

    SearchResultDone ::= [APPLICATION 5] LDAPResult
    """

    PROTOCOL_OP: ClassVar[int] = 4

    object_name: str
    partial_attributes: list[PartialAttribute]

    def to_asn1(self, enc: Encoder) -> None:
        """Serialize search response structure to asn1 buffer."""
        enc.write(self.object_name, Numbers.OctetString)
        enc.enter(Numbers.Sequence)

        for attr in self.partial_attributes:
            enc.enter(Numbers.Sequence)
            enc.write(attr.type, Numbers.OctetString)
            enc.enter(Numbers.Set)

            for val in attr.vals:
                enc.write(val, Numbers.OctetString)

            enc.leave()
            enc.leave()
        enc.leave()


class SearchResultDone(LDAPResult, BaseResponse):
    """LDAP result."""

    PROTOCOL_OP: ClassVar[int] = 5
    # API fields
    total_pages: int = 0
    total_objects: int = 0

    def _get_asn1_fields(self) -> dict:
        fields = super()._get_asn1_fields()
        fields.pop("total_pages")
        fields.pop("total_objects")
        return fields


INVALID_ACCESS_RESPONSE = {
    "result_code": LDAPCodes.OPERATIONS_ERROR,
    "errorMessage": (
        "000004DC: LdapErr: DSID-0C090A71, "
        "comment: In order to perform this operation "
        "a successful bind must be "
        "completed on the connection., data 0, v3839"
    ),
}


class SearchResultReference(BaseResponse):
    """List of uris."""

    PROTOCOL_OP: ClassVar[int] = 19

    values: list[AnyUrl]


class ModifyResponse(LDAPResult, BaseResponse):
    """Modify response."""

    PROTOCOL_OP: ClassVar[int] = 7


class AddResponse(LDAPResult, BaseResponse):
    """Modify response."""

    PROTOCOL_OP: ClassVar[int] = 9


class DeleteResponse(LDAPResult, BaseResponse):
    """Delete response."""

    PROTOCOL_OP: ClassVar[int] = 11


class ModifyDNResponse(LDAPResult, BaseResponse):
    """Delete response."""

    PROTOCOL_OP: ClassVar[int] = 13


class BaseExtendedResponseValue(ABC, BaseEncoder):
    """Base extended response proxy class."""

    @abstractmethod
    def get_value(self) -> str | None:
        """Get response value."""


class ExtendedResponse(LDAPResult, BaseResponse):
    """Described in RFC 4511 section 4.12.

    ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        COMPONENTS OF LDAPResult,
        responseName     [10] LDAPOID OPTIONAL,
        responseValue    [11] OCTET STRING OPTIONAL }
    """

    PROTOCOL_OP: ClassVar[int] = 24
    response_name: LDAPOID
    response_value: SerializeAsAny[BaseExtendedResponseValue] | None

    def to_asn1(self, enc: Encoder) -> None:
        """Serialize flat structure to bytes, write to encoder buffer."""
        enc.write(self.result_code, type_map[type(self.result_code)])
        enc.write(self.matched_dn, type_map[type(self.matched_dn)])
        enc.write(self.error_message, type_map[type(self.error_message)])

        if self.response_value and (value := self.response_value.get_value()):
            enc.write(value, type_map[type(value)])


# 15: 'compare Response'
# 19: 'Search Result Reference'
# 25: 'intermediate Response'
