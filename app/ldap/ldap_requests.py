"""LDAP requests structure bind."""

import asyncio
from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, Field

from .asn1parser import ASN1Row
from .codes import LDAPCodes
from .ldap_responses import BaseResponse, BindResponse


class BaseRequest(ABC, BaseModel):
    """Base request builder."""

    @property
    @abstractmethod
    def PROTOCOL_OP(self) -> int:  # noqa: N802, D102
        """Protocol OP response code."""

    @classmethod
    @abstractmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'BaseRequest':
        """Create structure from ASN1Row dataclass list."""
        raise NotImplementedError()

    def to_asn1(self, *args, **kwargs) -> None:  # noqa: D102
        raise NotImplementedError('No need to encode request')

    @abstractmethod
    async def handle(self, session) -> BaseResponse:
        """Handle message with current user."""


class SimpleAuthentication(BaseModel):
    password: str


class SaslAuthentication(BaseModel):
    mechanism: str
    credentials: bytes


class BindRequest(BaseRequest):
    """Bind request fields mapping."""

    PROTOCOL_OP: ClassVar[int] = 0x0

    version: int
    name: str
    authentication_choice: SimpleAuthentication | SaslAuthentication =\
        Field(..., alias='AuthenticationChoice')

    @classmethod
    def from_data(cls, data) -> 'BindRequest':
        """Get bind from data dict."""
        auth = data['field-1'][1].tag_id.value
        auth_data = data['field-2']

        if auth == 0:
            auth_choice = SimpleAuthentication(password=auth_data[2].value)
        elif auth == 3:  # TODO: Add SASL support
            raise NotImplementedError('Sasl not supported')
        else:
            raise ValueError('Auth version not supported')

        return cls(
            version=auth_data[0].value,
            name=auth_data[1].value,
            AuthenticationChoice=auth_choice,
        )

    async def handle(self, session) -> BindResponse:
        """Handle bind request, check user and password."""
        if session.name:
            raise ValueError('User authed')
        await asyncio.sleep(0)  # TODO: Add sqlalchemy query
        session.name = self.name
        return BindResponse(resultCode=LDAPCodes.SUCCESS)


class UnbindRequest(BaseRequest):
    pass


class SearchRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 3

    op: int = 1

    @classmethod
    def from_data(cls, data):
        return cls()


class ModifyRequest(BaseRequest):
    pass


class AddRequest(BaseRequest):
    pass


class DeleteRequest(BaseRequest):
    pass


class ModifyDNRequest(BaseRequest):
    pass


class CompareRequest(BaseRequest):
    pass


class AbandonRequest(BaseRequest):
    pass


class ExtendedRequest(BaseRequest):
    pass


# TODO: add support for all codes
protocol_id_map: dict[int, type[BaseRequest]] = {
    0: BindRequest,
    1: 'Bind Response',
    2: UnbindRequest,
    3: SearchRequest,
    4: 'search Result Entry',
    5: 'search Result Done',
    6: ModifyRequest,
    7: 'Modify Response',
    8: AddRequest,
    9: 'Add Response',
    10: DeleteRequest,
    11: 'Delete Response',
    12: ModifyDNRequest,
    13: 'Modify DN Response',
    14: CompareRequest,
    15: 'compare Response',
    16: AbandonRequest,
    19: 'Search Result Reference',
    23: ExtendedRequest,
    24: 'Extended Response',
    25: 'intermediate Response',
}