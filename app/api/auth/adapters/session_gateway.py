"""Gateway for session storage operations."""

from dataclasses import asdict, dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, ParamSpec, TypeVar

from fastapi import status

from api.base_adapter import BaseAdapter
from ldap_protocol.session_storage import SessionRepository

_P = ParamSpec("_P")
_R = TypeVar("_R")


@dataclass
class SessionContentResponseSchema:
    """Session content schema."""

    id: int
    sign: str
    issued: datetime
    ip: IPv4Address | IPv6Address
    protocol: Literal["ldap", "http"] = "http"
    user_agent: str = ""

    def __post_init__(self) -> None:
        """Post-initialization."""
        self.issued = (
            datetime.fromisoformat(self.issued)
            if isinstance(self.issued, str)  # type: ignore[unreachable]
            else self.issued
        )


@dataclass
class UserSessionsSchema:
    """User sessions schema."""

    upn: str
    ldap_session_count: int
    http_session_count: int


@dataclass
class UserSessionsResponseSchema:
    """User session response schema."""

    users: list[UserSessionsSchema]
    total_count: int


class SessionFastAPIGateway(BaseAdapter[SessionRepository]):
    """Base class for session storage."""

    _exceptions_map: dict[type[Exception], int] = {
        LookupError: status.HTTP_404_NOT_FOUND,
    }

    def __init__(self, repository: SessionRepository) -> None:
        """Initialize the session gateway with a repository."""
        self._service = repository

    async def get_user_sessions(
        self,
        upn: str,
    ) -> dict[str, SessionContentResponseSchema]:
        data = await self._service.get_user_sessions(upn)

        return {
            session_id: SessionContentResponseSchema(**asdict(data))
            for session_id, data in data.items()
        }

    async def delete_user_sessions(self, upn: str) -> None:
        """Delete user sessions."""
        await self._service.clear_user_sessions(upn)

    async def delete_session(self, session_id: str) -> None:
        """Delete user session."""
        return await self._service.delete_session(session_id)
