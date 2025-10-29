"""Identity provider.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abstract_dao import AbstractService
from config import Settings
from entities import User
from ldap_protocol.dialogue import UserSchema
from ldap_protocol.identity.exceptions.auth import UnauthorizedError
from ldap_protocol.identity.identity_provider_gateway import (
    IdentityProviderGateway,
)
from ldap_protocol.session_storage.base import SessionStorage


class IdentityProvider(AbstractService):
    """Manager for current user operations."""

    ip_from_request: str
    user_agent: str
    session_key: str

    def __init__(
        self,
        session_storage: SessionStorage,
        settings: Settings,
        identity_provider_gateway: IdentityProviderGateway,
    ) -> None:
        """Initialize manager.

        Args:
            identity_provider_gateway: Gateway for database operations.
            session_storage: Backend that stores session metadata.
            settings: Application settings with session constraints.

        """
        self.session_storage = session_storage
        self.settings = settings
        self.identity_provider_gateway = identity_provider_gateway

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
        user = await self.identity_provider_gateway.get_user(user_id)
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
                self.user_agent,
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
