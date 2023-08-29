"""LDAP message abstract structure."""
from abc import ABC, abstractmethod
from typing import AsyncGenerator

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import Session
from ldap_protocol.ldap_responses import BaseResponse


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
        raise NotImplementedError(f'Tried to access {cls.PROTOCOL_OP}')

    @abstractmethod
    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[BaseResponse, None]:
        """Handle message with current user."""
        yield BaseResponse()  # type: ignore

    class Config:  # noqa: D106
        fields = {'PROTOCOL_OP': {'exclude': True}}

    async def handle_api(
        self, user,
        session: AsyncSession,
        single: bool = True,
    ) -> list[BaseResponse] | BaseResponse:
        """Hanlde response with api user.

        :param DBUser user: user from db
        :param AsyncSession session: db session
        :return list[BaseResponse]: list of handled responses
        """
        responses = [
            response async for response in self.handle(
                Session(user=user), session)]

        if single:
            return responses[0]
        return responses
