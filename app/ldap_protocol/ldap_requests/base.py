"""LDAP message abstract structure.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, AsyncGenerator, Callable, ClassVar, Protocol

from dishka import AsyncContainer
from loguru import logger
from pydantic import BaseModel

from config import Settings
from ldap_protocol.dependency import resolve_deps
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.ldap_responses import BaseResponse, LDAPResult
from ldap_protocol.utils.helpers import get_class_name

log_api = logger.bind(name="admin")

log_api.add(
    "logs/admin_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "admin",
    retention="10 days",
    rotation="1d",
    colorize=False,
)

type handler = Callable[..., AsyncGenerator[BaseResponse, None]]
type serializer = Callable[..., "BaseRequest"]


if TYPE_CHECKING:

    class _APIProtocol(Protocol):
        """Protocol for API handling."""

        async def _handle_api(
            self,
            container: AsyncContainer,
        ) -> list[BaseResponse] | BaseResponse: ...
else:

    class _APIProtocol: ...


class BaseRequest(ABC, _APIProtocol, BaseModel):
    """Base request builder."""

    handle: ClassVar[handler]
    from_data: ClassVar[serializer]

    @property
    @abstractmethod
    def PROTOCOL_OP(self) -> int:  # noqa: N802
        """Protocol OP response code."""

    async def _handle_api(
        self,
        container: AsyncContainer,
    ) -> list[BaseResponse]:
        """Hanlde response with api user.

        :param DBUser user: user from db
        :param AsyncSession session: db session
        :return list[BaseResponse]: list of handled responses
        """
        handler = await resolve_deps(func=self.handle, container=container)
        ldap_session = await container.get(LDAPSession)
        settings = await container.get(Settings)

        un = getattr(ldap_session.user, "user_principal_name", "ANONYMOUS")

        if settings.DEBUG:
            log_api.info(f"{get_class_name(self)}: {self.model_dump_json()}")
        else:
            log_api.info(f"{get_class_name(self)}[{un}]")

        responses = [response async for response in handler()]

        if settings.DEBUG:
            for response in responses:
                log_api.info(
                    "{}: {}",
                    get_class_name(response),
                    response.model_dump_json(),
                )
        else:
            for response in responses:
                log_api.info(f"{get_class_name(response)}[{un}]")

        return responses

    async def handle_api(self, container: AsyncContainer) -> LDAPResult:
        """Get single response."""
        return (await self._handle_api(container))[0]  # type: ignore
