"""LDAP message abstract structure.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, AsyncGenerator, Protocol

from dishka import AsyncContainer
from loguru import logger
from pydantic import BaseModel

from config import Settings
from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dependency import resolve_deps
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.ldap_responses import BaseResponse
from ldap_protocol.utils.helpers import get_class_name

log_api = logger.bind(name='admin')

log_api.add(
    "logs/admin_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == 'admin',
    retention="10 days",
    rotation="1d",
    colorize=False)


if TYPE_CHECKING:
    class _APIProtocol(Protocol):
        """Protocol for API handling."""

        async def _handle_api(
            self, container: AsyncContainer,
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
    async def handle(self, *args: Any, **kwargs: Any) -> AsyncGenerator[
            BaseResponse, None]:
        """Handle message with current user."""

    async def _handle_api(
            self, container: AsyncContainer) -> list[BaseResponse]:
        """Hanlde response with api user.

        :param DBUser user: user from db
        :param AsyncSession session: db session
        :return list[BaseResponse]: list of handled responses
        """
        handler = await resolve_deps(func=self.handle, container=container)
        ldap_session = await container.get(LDAPSession)
        settings = await container.get(Settings)

        un = getattr(ldap_session.user, 'user_principal_name', 'ANONYMOUS')

        if settings.DEBUG:
            log_api.info(f"{get_class_name(self)}: {self.model_dump_json()}")
        else:
            log_api.info(f"{get_class_name(self)}[{un}]")

        responses = [response async for response in handler()]  # type: ignore

        if settings.DEBUG:
            for response in responses:
                log_api.info(
                    "{}: {}",
                    get_class_name(response),
                    response.model_dump_json())
        else:
            for response in responses:
                log_api.info(f"{get_class_name(response)}[{un}]")

        return responses

    async def handle_api(self, container: AsyncContainer) -> BaseResponse:
        """Get single response."""
        return (await self._handle_api(container))[0]


class APIMultipleResponseMixin(_APIProtocol):
    """Get multiple responses."""

    async def handle_api(
        self, container: AsyncContainer,
    ) -> list[BaseResponse]:
        """Get all responses."""
        return await self._handle_api(container)  # type: ignore
