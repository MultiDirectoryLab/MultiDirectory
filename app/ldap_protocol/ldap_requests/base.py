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
from models import Directory

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
    __event_data: dict = {}

    @property
    @abstractmethod
    def PROTOCOL_OP(self) -> int:  # noqa: N802
        """Protocol OP response code."""

    def set_event_data(self, data: dict) -> None:
        """Set event data."""
        self.__event_data = data

    def get_event_data(self) -> dict:
        """Get event data."""
        return self.__event_data

    def get_directory_attrs(self, directory: Directory) -> dict:
        """Get directory attrs."""
        attributes: dict[str, list] = {}
        obj_classes = []
        for attr in directory.attributes:
            attr_name = attr.name.lower()
            if attr_name == "objectclass":
                obj_classes.append(attr.value)

            if attr_name not in attributes:
                attributes[attr_name] = []

            attributes[attr_name].append(attr.value)

        if "group" in obj_classes or "user" in obj_classes:
            attributes["memberof"] = []
            for group in directory.groups:
                attributes["memberof"].append(group.directory.path_dn)

        if "group" in obj_classes and directory.group:
            attributes["member"] = []
            for member in directory.group.members:
                attributes["member"].append(member.path_dn)

        return attributes

    async def _handle_api(
        self,
        container: AsyncContainer,
    ) -> list[BaseResponse]:
        """Hanlde response with api user.

        :param DBUser user: user from db
        :param AsyncSession session: db session
        :return list[BaseResponse]: list of handled responses
        """
        kwargs = await resolve_deps(func=self.handle, container=container)
        ldap_session = await container.get(LDAPSession)
        settings = await container.get(Settings)

        un = getattr(ldap_session.user, "user_principal_name", "ANONYMOUS")

        if settings.DEBUG:
            log_api.info(f"{get_class_name(self)}: {self.model_dump_json()}")
        else:
            log_api.info(f"{get_class_name(self)}[{un}]")

        responses = [response async for response in self.handle(**kwargs)]

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
