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
    PROTOCOL_OP: ClassVar[int] = 2


class SearchRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 3

    op: int = 1

    @classmethod
    def from_data(cls, data):
        return cls()


class ModifyRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 6


class AddRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 8


class DeleteRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 10


class ModifyDNRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 12


class CompareRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 14


class AbandonRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 16


class ExtendedRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 23


protocol_id_map: dict[int, type[BaseRequest]] = \
    {request.PROTOCOL_OP: request  # type: ignore
        for request in BaseRequest.__subclasses__()}

# protocol_id_map: dict[int, type[BaseRequest]] = {
#     1: 'Bind Response',
#     4: 'search Result Entry',
#     5: 'search Result Done',
#     7: 'Modify Response',
#     9: 'Add Response',
#     11: 'Delete Response',
#     13: 'Modify DN Response',
#     15: 'compare Response',
#     19: 'Search Result Reference',
#     24: 'Extended Response',
#     25: 'intermediate Response',
# }
