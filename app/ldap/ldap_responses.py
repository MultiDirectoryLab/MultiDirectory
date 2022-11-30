"""LDAP response containers."""

from abc import ABC, abstractmethod
from typing import Any, ClassVar, get_type_hints

from asn1 import Encoder, Numbers
from pydantic import AnyUrl, BaseModel, Field

from .dialogue import LDAPCodes

type_map = {
    bool: Numbers.Boolean,
    int: Numbers.Integer,
    bytes: Numbers.BitString,
    str: Numbers.OctetString,
    None: Numbers.Null,
    LDAPCodes: Numbers.Enumerated,
}


class BaseResponse(ABC, BaseModel):
    """Base class for Response."""

    @property
    @abstractmethod
    def PROTOCOL_OP(self) -> int:  # noqa: N802, D102
        """Protocol OP response code."""

    def _get_fields_and_types(self) -> tuple[dict[str, Any], dict[str, Any]]:
        fields = self.dict()
        fields.pop('PROTOCOL_OP', None)
        return fields, get_type_hints(self)

    def to_asn1(self, enc: Encoder) -> None:
        """Serialize structure to bytes, write to encoder buffer."""
        fields, types = self._get_fields_and_types()
        for field_name, value in fields.items():
            enc.write(value, type_map[types[field_name]])


class BindResponse(BaseResponse):
    """Bind response."""

    PROTOCOL_OP: ClassVar[int] = 1

    result_code: LDAPCodes = Field(..., alias='resultCode')
    matched_dn: str = Field('', alias='matchedDN')
    error_message: str = Field('', alias="errorMessage")


class PartialAttribute(BaseModel):
    type: str  # noqa: A003
    vals: list[str]


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


class SearchResultDone(BaseResponse):
    """LDAP result."""

    PROTOCOL_OP: ClassVar[int] = 5


class SearchResultReference(BaseResponse):
    """List of uris."""

    PROTOCOL_OP: ClassVar[int] = 19

    values: list[AnyUrl]
