"""LDAP response containers."""

from abc import ABC, abstractmethod
from typing import ClassVar

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


class LDAPResult(BaseModel):
    """Base LDAP result structure."""

    result_code: LDAPCodes = Field(..., alias='resultCode')
    matched_dn: str = Field('', alias='matchedDN')
    error_message: str = Field('', alias="errorMessage")


class BaseResponse(ABC, BaseModel):
    """Base class for Response."""

    @property
    @abstractmethod
    def PROTOCOL_OP(self) -> int:  # noqa: N802, D102
        """Protocol OP response code."""

    def to_asn1(self, enc: Encoder) -> None:
        """Serialize flat structure to bytes, write to encoder buffer."""
        fields = self.dict()
        fields.pop('PROTOCOL_OP', None)
        for value in fields.values():
            enc.write(value, type_map[type(value)])


class BindResponse(LDAPResult, BaseResponse):
    """Bind response."""

    PROTOCOL_OP: ClassVar[int] = 1


class PartialAttribute(BaseModel):
    """Partial attribite structure. Description in rfc2251 4.1.6."""

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


BAD_SEARCH_RESPONSE = {
    'resultCode': LDAPCodes.OPERATIONS_ERROR,
    'errorMessage': (
        '000004DC: LdapErr: DSID-0C090A71, '
        'comment: In order to perform this operation '
        'a successful bind must be '
        'completed on the connection., data 0, v3839'),
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

#     13: 'Modify DN Response'
#     15: 'compare Response'
#     19: 'Search Result Reference'
#     24: 'Extended Response'
#     25: 'intermediate Response'
