"""LDAP message abstract structure."""
from abc import ABC, abstractmethod
from typing import AsyncGenerator

from loguru import logger
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import Session
from ldap_protocol.ldap_responses import BaseResponse

api_logger = logger.bind(event=True)

logger.add(
    "logs/json_ldap_{time:DD-MM-YYYY}.log",
    filter=lambda rec: "event" in rec["extra"],
    retention="10 days",
    rotation="1d",
    level='DEBUG',
    colorize=False,
    catch=True,
    serialize=False)


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
        api_logger.info(self.model_dump_json())

        responses = [
            response async for response in self.handle(
                Session(user=user), session)]

        for response in responses:
            api_logger.info(response.model_dump_json(indent=4))

        if single:
            return responses[0]
        return responses
