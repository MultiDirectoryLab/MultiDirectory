"""Session storage for http/ldap protocol."""

from __future__ import annotations

import hashlib
import hmac
import json
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timezone
from secrets import token_hex
from typing import Iterable, Self

from redis.asyncio import Redis

from config import Settings


class SessionStorage(ABC):
    """Abstract session storage class."""

    key_length: int = 16

    @abstractmethod
    async def get(self, key: str) -> dict:
        """Retrieve data associated with the given key from storage.

        :param str key: The key to look up in the storage.
        :return dict: The data associated with the key,
            or an empty dictionary if the key is not found.
        """

    @abstractmethod
    async def _get_user_keys(self, uid: int) -> set[str]:
        pass

    @abstractmethod
    async def get_user_sessions(self, uid: int) -> dict:
        """Get user sessions.

        :param int uid: user id
        :return dict: data
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

        :param int uid: user id
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

    def _get_id_hash(self, user_id: int) -> str:
        return hashlib.blake2b(
            str(user_id).encode(), digest_size=16).hexdigest()

    def _generate_key(self) -> str:
        """Generate a new key for storing data in the storage.

        :return str: A new key.
        """
        return token_hex(self.key_length)

    @abstractmethod
    async def create_session(
        self: Self,
        uid: int,
        settings: Settings,
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
    ) -> int:
        """Get user from storage.

        :param Settings settings: app settings
        :param str session_key: session key
        :return int: user id
        """
        try:
            session_id, signature = session_key.split(".")
        except (ValueError, AttributeError):
            raise KeyError('Invalid payload key')

        data = await self.get(session_id)

        if data is None or data.get("sign") != signature:
            raise KeyError('Invalid signature')

        expected_signature = self._sign(session_id, settings)
        user_id = data.get("id")

        if signature != expected_signature or user_id is None:
            raise KeyError('Invalid signature')

        return user_id

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


class RedisSessionStorage(SessionStorage):
    """Session storage for Session."""

    def __init__(self, storage: Redis, key_length: int, key_ttl: int) -> None:
        """Initialize the storage.

        :param Redis storage:
            The Redis/DragonflyDB instance to use for storage.
        :param int key_length: The length of the keys to generate.
        :param int key_ttl: The time-to-live for keys in seconds.
        """
        self._storage = storage
        self.key_length = key_length
        self.key_ttl = key_ttl

    async def get(self, key: str) -> dict:
        """Retrieve data associated with the given key from storage.

        :param str key: The key to look up in the storage.
        :return dict: The data associated with the key,
            or an empty dictionary if the key is not found.
        """
        data = await self._storage.get(key)
        if data is None:
            raise KeyError
        return json.loads(data)

    async def delete(self, keys: Iterable[str]) -> None:
        """Delete data associated with the given key from storage.

        :param str key: The key to delete from the storage.
        """
        await self._storage.delete(*keys)

    async def _get_user_keys(self, uid: int) -> set[str]:
        """Get user sessions."""
        keys = await self._storage.get(self._get_id_hash(uid))

        if keys is None:
            return set()

        return set(keys.split(b";"))

    async def get_user_sessions(self, uid: int) -> dict:
        """Get user sessions.

        :param UserSchema | int user: user id or user
        :return dict: user sessions contents
        """
        keys = await self._get_user_keys(uid)
        if not keys:
            return {}
        data = await self._storage.mget(*keys)
        return {k: json.loads(v) for k, v in zip(keys, data) if v is not None}

    async def clear_user_sessions(self, uid: int) -> None:
        """Clear user sessions."""
        keys = await self._get_user_keys(uid)
        await self.delete(keys)
        await self._storage.delete(self._get_id_hash(uid))

    async def delete_user_session(self, session_id: str) -> None:
        """Delete user session."""
        data = await self.get(session_id)
        uid = data.get("id")

        if uid is None:
            raise KeyError('Invalid session id')

        uid = int(uid)

        keys = await self._get_user_keys(uid)
        keys.remove(session_id)

        await self._storage.set(
            self._get_id_hash(uid),
            ";".join(keys),
            keepttl=True,
        )
        await self.delete([session_id])

    async def create_session(
        self: Self,
        uid: int,
        settings: Settings,
        *,
        extra_data: dict | None = None,
    ) -> str:
        """Create jwt token.

        :param int uid: user id
        :param dict data: data dict
        :param str secret: secret key
        :param int expires_minutes: exire time in minutes
        :param Literal[refresh, access] grant_type: grant type flag
        :return str: jwt token
        """
        if extra_data is None:
            extra_data = {}

        session_id = self._generate_key()
        signature = self._sign(session_id, settings)

        data = {"id": uid, "sign": signature} | extra_data
        data['issued'] = datetime.now(timezone.utc).isoformat()

        await self._storage.set(session_id, json.dumps(data), ex=self.key_ttl)
        await self._storage.append(self._get_id_hash(uid), f"{session_id};")

        return f"{session_id}.{signature}"

    async def check_session(self, session_id: str) -> bool:
        """Check session."""
        return await self._storage.exists(session_id)

    async def create_ldap_session(
            self, uid: int, key: str, data: dict) -> None:
        """Create ldap session.

        :param int uid: user id
        :param str key: session key
        :param dict data: any data
        """
        await self._storage.set(key, json.dumps(data), ex=None)
        await self._storage.append(key, self._get_id_hash(uid))


class MemSessionStorage(SessionStorage):
    """Test session storage."""

    def __init__(self) -> None:
        """Initialize the storage."""
        self._sessions: dict[str, dict[str, str]] = {}
        self._session_batch: defaultdict[str, list[str]] = defaultdict(list)

    async def get(self, key: str) -> dict[str, str]:
        """Get session data."""
        return self._sessions[key]

    async def _set_data(
            self, key: str, data: dict, expire: int | None) -> None:
        """Set session data."""
        self._sessions[key] = data

    async def delete(self, keys: Iterable[str]) -> None:
        """Delete session data."""
        for key in keys:
            if key in self._sessions:
                del self._sessions[key]

    async def _get_user_keys(self, uid: int) -> set[str]:
        """Get user sessions."""
        keys = self._session_batch.get(self._get_id_hash(uid))

        if keys is None:
            return set()

        return set(keys)

    async def get_user_sessions(self, uid: int) -> dict:
        """Get user sessions.

        :param UserSchema | int user: user id or user
        :return dict: user sessions contents
        """
        retval = {}  # type: dict

        keys = await self._get_user_keys(uid)
        if not keys:
            return retval

        for key in keys:
            retval[key] = self._sessions[key]

        return retval

    async def clear_user_sessions(self, user_id: int) -> None:
        """Clear user sessions."""
        uid = str(user_id)
        keys = await self._get_user_keys(user_id)

        for key in keys:
            if key in self._sessions:
                del self._sessions[key]

        del self._session_batch[uid]

    async def delete_user_session(self, session_id: str) -> None:
        """Delete user session."""
        data = self._sessions[session_id]
        tmp = data.get("id")

        if tmp is None:
            raise KeyError('Invalid session id')

        uid = int(tmp)

        keys = await self._get_user_keys(uid)
        keys.remove(session_id)

        self._session_batch[self._get_id_hash(uid)] = list(keys)
        await self.delete([session_id])

    async def create_session(
        self: Self,
        uid: int,
        settings: Settings,
        *,
        extra_data: dict | None = None,
    ) -> str:
        """Create jwt token.

        :param int uid: user id
        :param dict data: data dict
        :param str secret: secret key
        :param int expires_minutes: exire time in minutes
        :param Literal[refresh, access] grant_type: grant type flag
        :return str: jwt token
        """
        if extra_data is None:
            extra_data = {}

        session_id = self._generate_key()
        signature = self._sign(session_id, settings)

        data = {"id": uid, "sign": signature} | extra_data
        data['issued'] = datetime.now(timezone.utc).isoformat()

        self._sessions[session_id] = data
        self._session_batch[self._get_id_hash(uid)].append(session_id)

        return f"{session_id}.{signature}"

    async def check_session(self, session_id: str) -> bool:
        """Check session."""
        return session_id in self._sessions

    async def create_ldap_session(
            self, uid: int, key: str, data: dict) -> None:
        """Create ldap session.

        :param int uid: user id
        :param str key: session key
        :param dict data: any data
        """
        self._sessions[key] = data
        self._session_batch[key].append(self._get_id_hash(uid))
