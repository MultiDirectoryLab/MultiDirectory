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
    """Coordinate session validation and user retrieval for requests."""

    _ip_from_request: str
    _user_agent: str
    _session_key: str
    new_key: str | None = None

    def __init__(
        self,
        session_storage: SessionStorage,
        settings: Settings,
        identity_provider_gateway: IdentityProviderGateway,
        ip_from_request: str,
        user_agent: str,
        session_key: str,
    ) -> None:
        """Initialize identity provider with session context.

        Args:
            session_storage: Backend responsible for session metadata and TTL.
            settings: Application configuration containing session policies.
            identity_provider_gateway: Adapter that fetches user entities.
            ip_from_request: Client IP extracted from the incoming request.
            user_agent: User-Agent header associated with the request.
            session_key: Raw session cookie presented by the client.

        """
        self._session_storage = session_storage
        self._settings = settings
        self._identity_provider_gateway = identity_provider_gateway
        self._ip_from_request = ip_from_request
        self._user_agent = user_agent
        self._session_key = session_key
        self.new_key = None

    @property
    def key_ttl(self) -> int:
        """Return session key time-to-live in seconds.

        Returns:
            int: TTL for issued session keys.

        """
        return self._session_storage.key_ttl

    async def get(self, user_id: int) -> UserSchema:
        """Return the user schema for the supplied identifier.

        Args:
            user_id: Identifier of the user to load.

        Returns:
            UserSchema: Serializable schema populated from the database entity.

        Raises:
            UnauthorizedError: If the user cannot be found by the given ID.

        """
        user = await self._identity_provider_gateway.get_user(user_id)
        if user is None:
            raise UnauthorizedError("Could not validate credentials")

        session_id, _ = self._session_key.split(".")
        return await self.to_schema(user, session_id)

    async def get_current_user(self) -> UserSchema:
        """Resolve the current user and rotate the session key if needed.

        Returns:
            UserSchema: Schema representation of the authenticated user.

        """
        user = await self.get(await self.get_user_id())
        await self.rekey_session()
        return user

    async def get_user_id(self) -> int:
        """Return the user identifier stored in session metadata.

        Returns:
            int: Identifier of the authenticated user.

        Raises:
            UnauthorizedError: If the session cookie is missing or invalid.

        """
        try:
            user_id = await self._session_storage.get_user_id(
                self._settings,
                self._session_key,
                self._user_agent,
                self._ip_from_request,
            )
        except KeyError as err:
            raise UnauthorizedError("Could not validate credentials") from err

        return user_id

    async def rekey_session(self) -> str | None:
        """Rotate the session key when storage policies require it.

        Returns:
            str | None: New session key when rotated, otherwise ``None``.

        """
        session_id, _ = self._session_key.split(".")
        key = await self._session_storage.rekey_session_if_needed(
            session_id,
            self._settings,
        )
        if key:
            self.set_new_session_key(key)

        return key

    def set_new_session_key(self, key: str) -> None:
        """Set a new session key.

        Args:
            key: New session key to set.

        """
        self.new_key = key

    @staticmethod
    async def to_schema(user: User, session_id: str) -> UserSchema:
        """Convert an ORM entity into the dialogue schema with session data.

        Args:
            user: ORM entity representing the authenticated user.
            session_id: Session identifier associated with the user.

        Returns:
            UserSchema: Dialogue schema enriched with session metadata.

        """
        return await UserSchema.from_db(user, session_id)
