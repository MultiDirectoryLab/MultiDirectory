"""Session storage for http/ldap protocol."""

from __future__ import annotations

import hashlib
import hmac
import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from secrets import token_hex
from typing import TYPE_CHECKING, Iterable, Self

from redis.asyncio import Redis

from config import Settings

if TYPE_CHECKING:
    from redis.asyncio.lock import Lock


class SessionStorage(ABC):
    """Abstract session storage class."""

    ZSET_LDAP_SESSIONS: str = "sessions:ldap"
    ZSET_HTTP_SESSIONS: str = "sessions:http"

    key_length: int = 16
    key_ttl: int

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

    def get_user_agent_hash(self, user_agent: str) -> str:
        """Get user agent hash."""
        return hashlib.blake2b(user_agent.encode(), digest_size=6).hexdigest()

    def _get_id_hash(self, user_id: int) -> str:
        return (
            "keys:"
            + hashlib.blake2b(
                str(user_id).encode(),
                digest_size=16,
            ).hexdigest()
        )

    def _generate_key(self) -> str:
        """Generate a new key for storing data in the storage.

        :return str: A new key.
        """
        return token_hex(self.key_length)

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

    async def _get_lock(self, name: str, blocking_timeout: int = 5) -> Lock:
        """Get lock.

        :param str name: lock name
        :param int blocking_timeout: blocking timeout, defaults to 5
        :return Lock: lock object
        """
        return self._storage.lock(
            name=self._get_lock_key(name),
            blocking_timeout=blocking_timeout,
        )

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

        return set(filter(None, keys.decode().split(";")))

    async def get_user_sessions(self, uid: int) -> dict:
        """Get user sessions.

        :param UserSchema | int user: user id or user
        :return dict: user sessions contents
        """
        keys = await self._get_user_keys(uid)
        if not keys:
            return {}
        data = await self._storage.mget(*keys)

        retval = {}

        for k, v in zip(keys, data):
            if v is not None:
                tmp = json.loads(v)
                if k.startswith("ldap"):
                    tmp["protocol"] = "ldap"
                retval[k] = tmp

        return retval

    async def clear_user_sessions(self, uid: int) -> None:
        """Clear user sessions."""
        keys = await self._get_user_keys(uid)
        uid_hash = self._get_id_hash(uid)
        if not keys:
            return
        await self.delete(keys)
        await self.delete([uid_hash])
        await self._storage.zrem(self.ZSET_HTTP_SESSIONS, uid_hash)
        await self._storage.zrem(self.ZSET_LDAP_SESSIONS, uid_hash)

    async def delete_user_session(self, session_id: str) -> None:
        """Delete user session."""
        try:
            data = await self.get(session_id)
        except KeyError:
            return

        uid = data.get("id")

        if uid is None:
            raise KeyError("Invalid session id")

        uid = int(uid)
        uid_hash = self._get_id_hash(uid)
        lock = await self._get_lock(uid_hash)

        async with lock:
            keys = await self._get_user_keys(uid)
            try:
                keys.remove(session_id)
            except KeyError:
                pass
            else:
                protocols = {k.startswith("ldap:") for k in keys}

                if session_id.startswith("ldap:") and True not in protocols:
                    await self._storage.zrem(self.ZSET_LDAP_SESSIONS, uid_hash)

                if (
                    not session_id.startswith("ldap:")
                    and False not in protocols
                ):
                    await self._storage.zrem(self.ZSET_HTTP_SESSIONS, uid_hash)

                if keys:
                    await self._storage.set(
                        uid_hash,
                        ";".join(keys) + ";",
                        keepttl=True,
                    )
                else:
                    await self.delete([uid_hash])

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
        session_id, signature, data = self._generate_session_data(
            uid=uid,
            settings=settings,
            extra_data=extra_data,
        )
        uid_hash = self._get_id_hash(uid)

        await self._storage.set(session_id, json.dumps(data), ex=self.key_ttl)
        await self._storage.append(uid_hash, f"{session_id};")
        await self._storage.zadd(
            self.ZSET_HTTP_SESSIONS,
            {uid_hash: uid},
            nx=True,
        )

        return f"{session_id}.{signature}"

    async def check_session(self, session_id: str) -> bool:
        """Check session."""
        return await self._storage.exists(session_id)

    async def create_ldap_session(
        self,
        uid: int,
        key: str,
        data: dict,
    ) -> None:
        """Create ldap session.

        :param int uid: user id
        :param str key: session key
        :param dict data: any data
        """
        data["issued"] = datetime.now(timezone.utc).isoformat()
        uid_hash = self._get_id_hash(uid)

        await self._storage.set(key, json.dumps(data), ex=None)
        await self._storage.append(uid_hash, f"{key};")
        await self._storage.zadd(
            self.ZSET_LDAP_SESSIONS,
            {uid_hash: uid},
            nx=True,
        )

    async def check_rekey(self, session_id: str, rekey_interval: int) -> bool:
        """Check rekey.

        :param str session_id: session id
        :param int rekey_interval: rekey interval in seconds
        :return bool: True if rekey is needed
        """
        lock = await self._get_lock(session_id)

        if await lock.locked():
            return False

        data = await self.get(session_id)

        issued = datetime.fromisoformat(data.get("issued"))  # type: ignore
        return (datetime.now(timezone.utc) - issued).seconds > rekey_interval

    async def _rekey_session(self, session_id: str, settings: Settings) -> str:
        """Rekey session.

        :param str session_id: session id
        :param Settings settings: app settings
        :return str: jwt token
        """
        data = await self.get(session_id)

        tmp = data.get("id")
        if tmp is None:
            raise KeyError("Invalid session id")
        uid = int(tmp)

        ttl = await self._storage.ttl(session_id)
        extra_data = data.copy()
        extra_data.pop("sign", None)

        new_session_id, new_signature, new_data = self._generate_session_data(
            uid=uid,
            settings=settings,
            extra_data=extra_data,
        )
        uid_hash = self._get_id_hash(uid)

        await self._storage.set(new_session_id, json.dumps(new_data), ex=ttl)
        await self._storage.append(uid_hash, f"{new_session_id};")
        await self._storage.zadd(
            self.ZSET_HTTP_SESSIONS,
            {uid_hash: uid},
            nx=True,
        )

        await self.delete_user_session(session_id)

        return f"{new_session_id}.{new_signature}"

    async def rekey_session(self, session_id: str, settings: Settings) -> str:
        """Rekey session.

        :param str session_id: session id
        :param Settings settings: app settings
        :return str: jwt token
        """
        lock = await self._get_lock(session_id)

        async with lock:
            return await self._rekey_session(session_id, settings)
