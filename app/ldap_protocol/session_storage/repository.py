"""Enterprise Session Repository."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from sqlalchemy.ext.asyncio import AsyncSession

from abstract_dao import AbstractService
from config import Settings
from entities import User
from enums import ApiPermissionsType
from ldap_protocol.utils.queries import get_user, set_user_logon_attrs

from .redis import SessionStorage


@dataclass
class SessionContentDTO:
    """Session content schema."""

    id: int
    issued: str
    ip: IPv4Address | IPv6Address
    sign: str = ""
    protocol: Literal["ldap", "http"] = "http"
    user_agent: str = ""


@dataclass
class UserSessionsMetadataDTO:
    """User sessions schema."""

    upn: str
    ldap_session_count: int
    http_session_count: int


@dataclass
class AllUserSessionsDTO:
    """User session response schema."""

    users: list[UserSessionsMetadataDTO]
    total_count: int


class SessionRepository(AbstractService):
    """Repository for managing user sessions."""

    @classmethod
    def _usecase_api_permissions(cls) -> dict[str, ApiPermissionsType]:
        return {
            cls.get_user_sessions.__name__: ApiPermissionsType.SESSION_GET_USE_SESSIONS,  # noqa: E501
            cls.clear_user_sessions.__name__: ApiPermissionsType.SESSION_CLEAR_USE_SESSIONS,  # noqa: E501
            cls.delete_session.__name__: ApiPermissionsType.SESSSION_DELETE,
        }

    def __init__(
        self,
        storage: SessionStorage,
        session: AsyncSession,
        settings: Settings,
    ) -> None:
        """Initialize the enterprise session storage.

        :param SessionStorage storage: session storage
        """
        self.storage = storage
        self.session = session
        self.settings = settings

    async def create_session_key(
        self,
        user: User,
        ip: IPv4Address | IPv6Address,
        user_agent: str,
        ttl: int,
    ) -> str:
        """Create a session key for the user.

        :param User user: db user
        :param SessionStorage storage: session storage
        :param Settings settings: app settings
        :param ip: client IP
        :param user_agent: client user agent
        :return: session key (str)
        """
        key = await self.storage.create_session(
            user.id,
            self.settings,
            extra_data={
                "ip": str(ip),
                "user_agent": self.storage.get_user_agent_hash(user_agent),
            },
            ttl=ttl,
        )

        await set_user_logon_attrs(user, self.session, self.settings.TIMEZONE)
        return key

    async def get_user_sessions(
        self,
        upn: str,
    ) -> dict[str, SessionContentDTO]:
        """Get user sessions by user ID.

        :param int user_id: user id
        :return dict[str, SessionContentDTO]: user sessions
        """
        user = await get_user(self.session, upn)

        if not user:
            raise LookupError("User not found.")

        sessions = await self.storage.get_user_sessions(user.id)

        return {k: SessionContentDTO(**v) for k, v in sessions.items()}

    async def clear_user_sessions(self, upn: str) -> None:
        """Clear user sessions by user ID.

        :param str upn: user principal name
        :raises KeyError: if user not found
        """
        user = await get_user(self.session, upn)

        if not user:
            raise LookupError("User not found.")

        await self.storage.clear_user_sessions(user.id)

    async def delete_session(self, session_id: str) -> None:
        """Delete user session by session ID.

        :param str session_id: session id
        """
        await self.storage.delete_user_session(session_id)
