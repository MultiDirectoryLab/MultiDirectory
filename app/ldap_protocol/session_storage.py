"""Session storage for http/ldap protocol."""

from __future__ import annotations

import hashlib
import hmac
import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from secrets import token_hex
from typing import TYPE_CHECKING, Iterable, Literal, Self

from redis.asyncio import Redis

from config import Settings

if TYPE_CHECKING:
    from redis.asyncio.lock import Lock

ProtocolType = Literal["http", "ldap"]


class SessionStorage(ABC):
    """Abstract session storage class."""

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
    async def _get_session_keys_by_user_id(self, uid: int) -> set[str]:
        pass

    @abstractmethod
    async def _get_session_keys_by_ip(self, ip: str) -> set[str]:
        pass

    @abstractmethod
    async def get_user_sessions(
        self,
        uid: int,
        protocol: ProtocolType | None = None,
    ) -> dict:
        """Get sessions by user id.

        :param UserSchema | int user: user id or user
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
        return hashlib.blake2b(
            str(user_id).encode(),
            digest_size=16,
        ).hexdigest()

    def _get_ip_session_key(
        self,
        ip: str,
        protocol: ProtocolType,
    ) -> str:
        return f"ip:{protocol}:{ip}"

    def _get_user_session_key(
        self,
        user_id: int,
        protocol: ProtocolType,
    ) -> str:
        return f"keys:{protocol}:{self._get_id_hash(user_id)}"

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

    async def _fetch_keys(self, key: str) -> set[str]:
        encoded_keys = await self._storage.smembers(key)  # type: ignore
        return {k.decode() for k in encoded_keys}

    async def _get_session_keys_by_ip(
        self,
        ip: str,
        protocol: ProtocolType | None = None,
    ) -> set[str]:
        """Get session keys by ip."""
        if protocol:
            return await self._fetch_keys(
                self._get_ip_session_key(ip, protocol),
            )

        return (
            await self._fetch_keys(self._get_ip_session_key(ip, "http"))
        ).union(await self._fetch_keys(self._get_ip_session_key(ip, "ldap")))

    async def _get_session_keys_by_user_id(
        self,
        uid: int,
        protocol: ProtocolType | None = None,
    ) -> set[str]:
        """Get sesssion keys by user id."""
        if protocol:
            return await self._fetch_keys(
                self._get_user_session_key(uid, protocol),
            )

        return (
            await self._fetch_keys(self._get_user_session_key(uid, "http"))
        ).union(
            await self._fetch_keys(self._get_user_session_key(uid, "ldap"))
        )

    async def get_user_sessions(
        self,
        uid: int,
        protocol: ProtocolType | None = None,
    ) -> dict:
        """Get sessions by user id.

        :param UserSchema | int user: user id or user
        :param ProtocolType | None protocol: protocol
        :return dict: user sessions contents
        """
        keys = await self._get_session_keys_by_user_id(uid, protocol)
        if not keys:
            return {}

        data = await self._storage.mget(*keys)
        retval = {}
        key_sessions_map: dict = {}
        for k, v in zip(keys, data):
            if v is not None:
                tmp = json.loads(v)
                if k.startswith("ldap:"):
                    tmp["protocol"] = "ldap"
                retval[k] = tmp
            else:
                protocol = self._get_protocol(k)
                key_sessions_map.setdefault(
                    self._get_user_session_key(uid, protocol),
                    [],
                ).append(k)

        if key_sessions_map:
            async with self._storage.pipeline(transaction=False) as pipe:
                for key, sessions in key_sessions_map.items():
                    await pipe.srem(key, *sessions)  # type: ignore
                await pipe.execute()

        return retval

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
        keys = await self._get_session_keys_by_ip(ip, protocol)
        if not keys:
            return {}

        data = await self._storage.mget(*keys)
        retval = {}
        key_sessions_map: dict = {}
        for k, v in zip(keys, data):
            if v is not None:
                tmp = json.loads(v)
                if k.startswith("ldap:"):
                    tmp["protocol"] = "ldap"
                retval[k] = tmp
            else:
                protocol = self._get_protocol(k)
                key_sessions_map.setdefault(
                    self._get_ip_session_key(ip, protocol),
                    [],
                ).append(k)

        if key_sessions_map:
            async with self._storage.pipeline(transaction=False) as pipe:
                for key, sessions in key_sessions_map.items():
                    await pipe.srem(key, *sessions)  # type: ignore
                await pipe.execute()

        return retval

    async def clear_user_sessions(
        self,
        uid: int,
    ) -> None:
        """Clear user sessions."""
        keys = await self._get_session_keys_by_user_id(uid)
        if not keys:
            return
        data = await self._storage.mget(*keys)

        key_sessions_map: dict = {}
        for k, v in zip(keys, data):
            if v is not None:
                tmp = json.loads(v)
                protocol = self._get_protocol(k)
                if ip := tmp.get("ip"):
                    key_sessions_map.setdefault(
                        self._get_ip_session_key(ip, protocol),
                        [],
                    ).append(k)

        http_sessions_key = self._get_user_session_key(uid, "http")
        ldap_sessions_key = self._get_user_session_key(uid, "ldap")

        async with self._storage.pipeline(transaction=False) as pipe:
            for key, sessions in key_sessions_map.items():
                if sessions:
                    await pipe.srem(  # type: ignore
                        key,
                        *sessions,
                    )
            await pipe.delete(*keys, http_sessions_key, ldap_sessions_key)
            await pipe.execute()

    async def delete_ip_session(self, ip: str, session_id: str) -> None:
        """Delete ip session."""
        protocol = self._get_protocol(session_id)
        await self._storage.srem(  # type: ignore
            self._get_ip_session_key(ip, protocol),
            session_id,
        )

    async def delete_user_session(self, session_id: str) -> None:
        """Delete user session."""
        try:
            data = await self.get(session_id)
        except KeyError:
            return

        uid = data.get("id")
        ip = data.get("ip")

        if uid is None or ip is None:
            raise KeyError("Invalid session id")

        uid = int(uid)

        protocol = self._get_protocol(session_id)

        sessions_key = self._get_user_session_key(uid, protocol)
        ip_key = self._get_ip_session_key(ip, protocol)
        lock = await self._get_lock(sessions_key)

        async with lock:
            await self._storage.srem(sessions_key, session_id)  # type: ignore
            await self._storage.srem(ip_key, session_id)  # type: ignore
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
        http_sessions_key = self._get_user_session_key(uid, "http")

        if extra_data and (ip := extra_data.get("ip")):
            await self._storage.sadd(  # type: ignore
                self._get_ip_session_key(ip, "http"),
                session_id,
            )

        await self._storage.set(session_id, json.dumps(data), ex=self.key_ttl)
        await self._storage.sadd(http_sessions_key, session_id)  # type: ignore

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
        ldap_sessions_key = self._get_user_session_key(uid, "ldap")

        if data and (ip := data.get("ip")):
            await self._storage.sadd(  # type: ignore
                self._get_ip_session_key(ip, "ldap"),
                key,
            )

        await self._storage.set(key, json.dumps(data), ex=None)
        await self._storage.sadd(ldap_sessions_key, key)  # type: ignore

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
        http_sessions_key = self._get_user_session_key(uid, "http")

        await self._storage.set(new_session_id, json.dumps(new_data), ex=ttl)
        await self._storage.sadd(http_sessions_key, new_session_id)  # type: ignore

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
