"""LDAP message abstract structure."""
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, AsyncGenerator, Protocol

from loguru import logger
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import Session, User
from ldap_protocol.ldap_responses import BaseResponse
from ldap_protocol.utils import get_class_name

api_logger = logger.bind(event=True)


if TYPE_CHECKING:
    class _APIProtocol(Protocol):
        """Protocol for API handling."""

        async def _handle_api(
            self, user: User,
            session: AsyncSession,
        ) -> list[BaseResponse] | BaseResponse: ...
else:
    class _APIProtocol: ...  # noqa


class BaseRequest(ABC, BaseModel, _APIProtocol):
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

    async def _handle_api(
        self, ldap_session: Session,
        session: AsyncSession,
    ) -> list[BaseResponse]:
        """Hanlde response with api user.

        :param DBUser user: user from db
        :param AsyncSession session: db session
        :return list[BaseResponse]: list of handled responses
        """
        un = getattr(ldap_session.user, 'user_principal_name', 'ANONYMOUS')
        api_logger.info(f"{get_class_name(self)}[{un}]")

        responses = [
            response async for response in self.handle(ldap_session, session)]

        for response in responses:
            api_logger.info(f"{get_class_name(response)}[{un}]")

        return responses

    async def handle_api(
        self, ldap_session: Session,
        session: AsyncSession,
    ) -> BaseResponse:
        """Get single response."""
        return (await self._handle_api(ldap_session, session))[0]


class APIMultipleResponseMixin(_APIProtocol):
    """Get multiple responses."""

    async def handle_api(
        self, user: User,
        session: AsyncSession,
    ) -> list[BaseResponse]:
        """Get all responses."""
        return await self._handle_api(user, session)
