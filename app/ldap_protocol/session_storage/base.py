"""Session storage for http/ldap protocol."""

from __future__ import annotations

import hashlib
import hmac
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from secrets import token_hex
from typing import Literal, Self

from config import Settings

ProtocolType = Literal["http", "ldap"]


class SessionStorage(ABC):
    """Abstract session storage class."""

    key_length: int = 16
    key_ttl: int

    ZSET_LDAP_SESSIONS: str = "sessions:ldap"
    ZSET_HTTP_SESSIONS: str = "sessions:http"

    @abstractmethod
    async def get(self, key: str) -> dict:
        """Retrieve data associated with the given key from storage.

        :param str key: The key to look up in the storage.
        :return dict: The data associated with the key,
            or an empty dictionary if the key is not found.
        """

    @abstractmethod
    async def _get_session_keys_by_uid(self, uid: int) -> set[str]:
        """Get session keys by user id.

        :param int uid: user id
        :return set[str]: session keys
        """

    @abstractmethod
    async def _get_session_keys_by_ip(self, ip: str) -> set[str]:
        """Get session keys by ip.

        :param str ip: ip
        :return set[str]: session keys
        """

    @abstractmethod
    async def get_user_sessions(
        self,
        uid: int,
        protocol: ProtocolType | None = None,
    ) -> dict:
        """Get sessions by user id.

        :param int uid: user id
        :param ProtocolType | None protocol: protocol
        :return dict: user sessions contents
        """

    @abstractmethod
    async def get_ip_sessions(
        self,
        ip: str,
        protocol: ProtocolType | None = None,
    ) -> dict:
        """Get sessions data by ip.

        :param str ip: ip
        :param ProtocolType | None protocol: protocol
        :return dict: user sessions contents
        """

    @abstractmethod
    async def clear_user_sessions(self, uid: int) -> None:
        """Clear user sessions.

        :param int uid: user id
        :return None:
        """

    @abstractmethod
    async def delete_user_session(self, session_id: str) -> None:
        """Delete user session.

        :param str session_id: session id
        :return None:
        """

    @staticmethod
    def _sign(session_id: str, settings: Settings) -> str:
        return hmac.new(
            settings.SECRET_KEY.encode(),
            session_id.encode(),
            hashlib.sha256,
        ).hexdigest()

    def get_user_agent_hash(self, user_agent: str) -> str:
        """Get user agent hash."""
        return hashlib.blake2b(user_agent.encode(), digest_size=6).hexdigest()

    def _get_ip_session_key(self, ip: str, protocol: ProtocolType) -> str:
        return f"ip:{protocol}:{ip}"

    def _get_user_session_key(self, uid: int, protocol: ProtocolType) -> str:
        return f"keys:{protocol}:{uid}"

    def _get_protocol(self, session_id: str) -> ProtocolType:
        return "http" if session_id.startswith("http:") else "ldap"

    def _generate_key(self) -> str:
        """Generate a new key for storing data in the storage.

        :return str: A new key.
        """
        return f"http:{token_hex(self.key_length)}"

    def _get_lock_key(self, session_id: str) -> str:
        """Get lock key.

        :param str session_id: session id
        :return str: lock key
        """
        return f"lock:{session_id}"

    @abstractmethod
    async def create_session(
        self: Self,
        uid: int,
        settings: Settings,
        ttl: int,
        *,
        extra_data: dict | None = None,
    ) -> str:
        """Create session.

        :param int uid: user id
        :param Settings settings: app settings
        :param dict | None extra_data: data, defaults to None
        :return str: session id
        """

    async def get_user_id(
        self: Self,
        settings: Settings,
        session_key: str,
        user_agent: str,
        ip: str,
    ) -> int:
        """Get user from storage.

        :param Settings settings: app settings
        :param str session_key: session key
        :param str user_agent: user agent
        :param str ip: ip address
        :return int: user id
        """
        try:
            session_id, signature = session_key.split(".")
        except (ValueError, AttributeError):
            raise KeyError("Invalid payload key")

        data = await self.get(session_id)
        expected_ua_hash = self.get_user_agent_hash(user_agent)
        expected_signature = self._sign(session_id, settings)

        if data is None:
            raise KeyError("Session data is missing")

        if data.get("ip") != ip:
            raise KeyError("Invalid ip")

        if data.get("user_agent") != expected_ua_hash:
            raise KeyError("Invalid user agent")

        if not (data.get("sign") == signature == expected_signature):
            raise KeyError("Invalid signature")

        user_id = data.get("id")
        if user_id is None:
            raise KeyError("Invalid data")

        return user_id

    def _generate_session_data(
        self: Self,
        uid: int,
        settings: Settings,
        extra_data: dict | None,
    ) -> tuple[str, str, dict]:
        """Set data."""
        if extra_data is None:
            extra_data = {}

        session_id = self._generate_key()
        signature = self._sign(session_id, settings)

        data = {"id": uid, "sign": signature} | extra_data
        data["issued"] = datetime.now(timezone.utc).isoformat()
        return session_id, signature, data

    @abstractmethod
    async def check_session(self, session_id: str) -> bool:
        """Check session.

        :param str session_id: session id
        :return bool: True if session exists
        """

    @abstractmethod
    async def create_ldap_session(
        self: Self,
        uid: int,
        key: str,
        data: dict,
    ) -> None:
        """Create ldap session.

        :param int uid: user id
        :param dict data: data, defaults to None
        """

    @abstractmethod
    async def check_rekey(self, session_id: str, rekey_interval: int) -> bool:
        """Check rekey.

        :param str session_id: session id
        :param int rekey_interval: rekey interval in seconds
        :return bool: True if rekey is needed
        """

    @abstractmethod
    async def rekey_session(self, session_id: str, settings: Settings) -> str:
        """Rekey session.

        :param str session_id: session id
        :param Settings settings: app settings
        :return str: jwt token
        """
