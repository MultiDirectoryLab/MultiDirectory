"""Gateway for session storage operations."""

from dataclasses import asdict, dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Awaitable, Callable, Literal, ParamSpec, TypeVar

from fastapi import HTTPException, status

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


class SessionFastAPIGateway:
    """Base class for session storage."""

    def __init__(self, repository: SessionRepository) -> None:
        """Initialize the session gateway with a repository."""
        self.repository = repository

    async def _sc(
        self,
        func: Callable[_P, Awaitable[_R]],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> _R:
        """Call function and convert exceptions to HTTPException."""
        try:
            return await func(*args, **kwargs)
        except KeyError as exc:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail=str(exc.args[0]),
            )

    async def get_user_sessions(
        self,
        upn: str,
    ) -> dict[str, SessionContentResponseSchema]:
        data = await self._sc(self.repository.get_user_sessions, upn)

        return {
            session_id: SessionContentResponseSchema(**asdict(data))
            for session_id, data in data.items()
        }

    async def delete_user_sessions(self, upn: str) -> None:
        """Delete user sessions."""
        await self._sc(self.repository.clear_user_sessions, upn)

    async def delete_session(self, session_id: str) -> None:
        """Delete user session."""
        return await self._sc(self.repository.delete_session, session_id)
