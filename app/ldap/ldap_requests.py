"""LDAP requests structure bind."""

import asyncio
import sys
from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, Field, validator

from .asn1parser import ASN1Row
from .dialogue import LDAPCodes, Session
from .ldap_responses import (BaseResponse, BindResponse, SearchResultDone,
                             SearchResultEntry, SearchResultReference)
from .objects import DerefAliases, Scope


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
    async def handle(self, session: Session) -> BaseResponse:
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

    async def handle(self, session: Session) -> BindResponse:
        """Handle bind request, check user and password."""
        if session.name:
            raise ValueError('User authed')
        await asyncio.sleep(0)  # TODO: Add sqlalchemy query
        session.name = self.name
        return BindResponse(resultCode=LDAPCodes.SUCCESS)


class UnbindRequest(BaseRequest):
    """Remove user from session."""

    PROTOCOL_OP: ClassVar[int] = 2

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'UnbindRequest':
        """Unbind request has no body."""
        return cls()

    async def handle(self, session: Session) -> BindResponse:
        """Handle unbind request, no need to send."""
        if not session.name:
            raise ValueError('User authed')
        await asyncio.sleep(0)  # TODO: Add sqlalchemy query
        missing_user = session.name
        session.name = None
        raise UserWarning(f'Unbind {missing_user}')


class SearchRequest(BaseRequest):
    """Search request schema.

    SearchRequest ::= [APPLICATION 3] SEQUENCE {
    baseObject      LDAPDN,
    scope           ENUMERATED {
        baseObject              (0),
        singleLevel             (1),
        wholeSubtree            (2),
        subordinateSubtree      (3),
    },
    derefAliases    ENUMERATED {
        neverDerefAliases       (0),
        derefInSearching        (1),
        derefFindingBaseObj     (2),
        derefAlways             (3) },
    sizeLimit       INTEGER (0 ..  maxInt),
    timeLimit       INTEGER (0 ..  maxInt),
    typesOnly       BOOLEAN,
    filter          Filter,
    attributes      AttributeSelection
    }
    """

    PROTOCOL_OP: ClassVar[int] = 3

    base_object: str | None
    scope: Scope
    deref_aliases: DerefAliases
    size_limit: int = Field(ge=0, le=sys.maxsize)
    time_limit: int = Field(ge=0, le=sys.maxsize)
    types_only: bool
    filter: str  # noqa: A003
    attributes: list[str]

    @classmethod
    def from_data(cls, data):  # noqa: D102
        (
            base_object,
            scope,
            deref_aliases,
            size_limit,
            time_limit,
            types_only,
            filter_,
            attributes_link,
        ) = data['field-2']

        return cls(
            base_object=base_object.value,
            scope=int(scope.value),
            deref_aliases=int(deref_aliases.value),
            size_limit=size_limit.value,
            time_limit=time_limit.value,
            types_only=types_only.value,
            filter=filter_.value,
            attributes=[field.value for field in data[attributes_link.value]],
        )

    @validator('base_object')
    def empty_str_to_none(cls, v):  # noqa: N805
        """Set base_object value to None if it's value is empty str."""
        if v == '':
            return None
        return v

    async def handle(
        self, session: Session,
    ) -> SearchResultDone | SearchResultReference | SearchResultEntry:
        await asyncio.sleep(0)
        return


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

# protocol_id_map: dict[int, type[BaseResponse]] = {
#     7: 'Modify Response',
#     9: 'Add Response',
#     11: 'Delete Response',
#     13: 'Modify DN Response',
#     15: 'compare Response',
#     19: 'Search Result Reference',
#     24: 'Extended Response',
#     25: 'intermediate Response',
# }
