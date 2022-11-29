from abc import ABC, abstractmethod
from typing import ClassVar, get_type_hints

from asn1 import Encoder, Numbers
from pydantic import BaseModel, Field

from .codes import LDAPCodes

type_map = {
    bool: Numbers.Boolean,
    int: Numbers.Integer,
    bytes: Numbers.BitString,
    str: Numbers.OctetString,
    None: Numbers.Null,
    LDAPCodes: Numbers.Integer,
}


class BaseResponse(ABC, BaseModel):
    """Base class for Response."""

    @property
    @abstractmethod
    def PROTOCOL_OP(self) -> int:  # noqa: N802, D102
        """Protocol OP response code."""

    def to_asn1(self, enc: Encoder) -> None:
        """Serialize structure to bytes."""
        fields = self.dict()
        fields.pop('PROTOCOL_OP', None)
        types = get_type_hints(self)
        for field_name, value in fields.items():
            enc.write(value, type_map[types[field_name]])


class BindResponse(BaseResponse):
    """Bind response."""

    PROTOCOL_OP: ClassVar[int] = 1

    result_code: LDAPCodes = Field(..., alias='resultCode')
    matched_dn: str = Field('', alias='matchedDN')
    error_message: str = Field('', alias="errorMessage")
