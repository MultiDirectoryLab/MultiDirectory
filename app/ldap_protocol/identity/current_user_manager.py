"""Current user manager.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from abstract_dao import AbstractService
from config import Settings
from entities import Group, User
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.identity.exceptions.auth import (
    LoginFailedError,
    UnauthorizedError,
)
from ldap_protocol.session_storage.base import SessionStorage
from repo.pg.tables import queryable_attr as qa


class CurrentUserManager(AbstractService):
    """Manager for current user operations."""

    def __init__(
        self,
        session: AsyncSession,
        session_storage: SessionStorage,
        request: Request,
        settings: Settings,
    ) -> None:
        """Initialize manager with persistence and request context.

        Args:
            session: Database session used for loading user entities.
            session_storage: Backend that stores session metadata.
            request: Current FastAPI request carrying cookies and headers.
            settings: Application settings with session constraints.

        """
        self.session = session
        self.request = request
        self.session_storage = session_storage
        self.settings = settings

    @property
    def session_key(self) -> str:
        """Return raw session key extracted from the request cookie.

        Returns:
            str: Session identifier or empty string when the cookie is missing.

        """
        return self.request.cookies.get("id", "")

    @property
    def ip_from_request(self) -> str:
        """Return client IP derived from headers or socket metadata.

        Returns:
            str: Client IP address.

        Raises:
            LoginFailedError: If the socket metadata is unavailable.

        """
        forwarded_for = self.request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0]
        else:
            if self.request.client is None:
                raise LoginFailedError("Login forbidden")
            client_ip = self.request.client.host

        return client_ip

    @property
    def user_agent_from_request(self) -> str:
        """Return user-agent string extracted from the request headers.

        Returns:
            str: User-Agent header or empty string if it is absent.

        """
        user_agent_header = self.request.headers.get("User-Agent")
        return user_agent_header if user_agent_header else ""

    @property
    def key_ttl(self) -> int:
        """Return session key time-to-live in seconds.

        Returns:
            int: TTL for issued session keys.

        """
        return self.session_storage.key_ttl

    async def get(self, user_id: int) -> UserSchema:
        """Load the authenticated user using request-bound session data.

        Args:
            user_id: Identifier of the user to load.

        Returns:
            UserSchema: Serializable schema populated from the database entity.

        Raises:
            UnauthorizedError: If the user cannot be found by the given ID.

        """
        user = await self.session.scalar(
            select(User)
            .filter_by(id=user_id)
            .options(joinedload(qa(User.directory)))
            .options(
                selectinload(qa(User.groups)).selectinload(qa(Group.roles)),
            ),
        )
        if user is None:
            raise UnauthorizedError("Could not validate credentials")

        session_id, _ = self.session_key.split(".")
        return await self.to_schema(user, session_id)

    async def get_current_user(self) -> UserSchema:
        """Load the authenticated user using request-bound session data.

        Returns:
            UserSchema: Serializable schema populated from the database entity.

        """
        user_id = await self.get_user_id()
        return await self.get(user_id)

    async def get_user_id(self) -> int:
        """Resolve user identifier based on the current session data.

        Returns:
            int: Identifier of the authenticated user.

        Raises:
            UnauthorizedError: If the session cookie is missing or invalid.

        """
        try:
            user_id = await self.session_storage.get_user_id(
                self.settings,
                self.session_key,
                self.user_agent_from_request,
                self.ip_from_request,
            )
        except KeyError as err:
            raise UnauthorizedError("Could not validate credentials") from err

        return user_id

    async def rekey_session(self) -> str | None:
        """Refresh session key when rotation is required.

        Returns:
            str | None: New session key when rotated, otherwise ``None``.

        """
        session_id, _ = self.session_key.split(".")
        key = await self.session_storage.rekey_session_if_needed(
            session_id,
            self.settings,
        )
        return key

    @staticmethod
    async def to_schema(user: User, session_id: str) -> UserSchema:
        """Convert database entity to transport schema with session state.

        Args:
            user: ORM entity representing the authenticated user.
            session_id: Session identifier associated with the user.

        Returns:
            UserSchema: Dialogue schema enriched with session metadata.

        """
        return await UserSchema.from_db(user, session_id)
