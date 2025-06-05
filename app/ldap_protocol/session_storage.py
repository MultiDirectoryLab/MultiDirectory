"""Session storage for http/ldap protocol."""

from __future__ import annotations

import hashlib
import hmac
import json
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import UTC, datetime
from secrets import token_hex
from typing import Iterable, Literal, Self

from redis.asyncio import Redis
from redis.asyncio.lock import Lock

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

        Args:
            key (str): The key to look up in the storage.

        Returns:
            dict: The data associated with the key, or an empty
            dictionary if the key is not found.
        """

    @abstractmethod
    async def _get_session_keys_by_uid(self, uid: int) -> set[str]:
        """Get session keys by user id.

        Args:
            uid (int): user id

        Returns:
            set[str]: session keys
        """

    @abstractmethod
    async def _get_session_keys_by_ip(self, ip: str) -> set[str]:
        """Get session keys by ip.

        Args:
            ip (str): ip

        Returns:
            set[str]: session keys
        """

    @abstractmethod
    async def get_user_sessions(
        self,
        uid: int,
        protocol: ProtocolType | None = None,
    ) -> dict:
        """Get sessions by user id.

        Args:
            uid (int): user id
            protocol (ProtocolType | None): The protocol type to filter\
                sessions by (e.g., "http" or "ldap"). If None,\
                sessions for all protocols are returned.

        Returns:
            dict: user sessions contents
        """

    @abstractmethod
    async def get_ip_sessions(
        self,
        ip: str,
        protocol: ProtocolType | None = None,
    ) -> dict:
        """Get sessions data by ip.

        Args:
            ip (str): ip
            protocol (ProtocolType | None): The protocol type to filter\
                sessions by (e.g., "http" or "ldap"). If None,\
                sessions for all protocols are returned.

        Returns:
            dict: user sessions contents
        """

    @abstractmethod
    async def clear_user_sessions(self, uid: int) -> None:
        """Clear user sessions.

        Args:
            uid (int): user id
        """

    @abstractmethod
    async def delete_user_session(self, session_id: str) -> None:
        """Delete user session.

        Args:
            session_id (str): session id
        """

    @staticmethod
    def _sign(session_id: str, settings: Settings) -> str:
        """Sign session id.

        Args:
            session_id (str): Session id
            settings (Settings): Settings with database dsn.

        Returns:
            str: The HMAC signature for the session_id using provided settings.
        """
        return hmac.new(
            settings.SECRET_KEY.encode(),
            session_id.encode(),
            hashlib.sha256,
        ).hexdigest()

    def get_user_agent_hash(self, user_agent: str) -> str:
        """Get user agent hash.

        Args:
            user_agent (str): user agent

        Returns:
            str: The hash of the user agent.
        """
        return hashlib.blake2b(user_agent.encode(), digest_size=6).hexdigest()

    def _get_ip_session_key(self, ip: str, protocol: ProtocolType) -> str:
        """Get ip session key.

        Args:
            ip (str): IP
            protocol (ProtocolType): Type of Protocol

        Returns:
            str: The session key for the given IP and protocol.
        """
        return f"ip:{protocol}:{ip}"

    def _get_user_session_key(self, uid: int, protocol: ProtocolType) -> str:
        """Get user session key.

        Args:
            uid (int): uid
            protocol (ProtocolType): Type of Protocol

        Returns:
            str: The session key for the given user and protocol.
        """
        return f"keys:{protocol}:{uid}"

    def _get_protocol(self, session_id: str) -> ProtocolType:
        """Get protocol.

        Args:
            session_id (str): Session id

        Returns:
            ProtocolType: Protocol type for given session_id
        """
        return "http" if session_id.startswith("http:") else "ldap"

    def _generate_key(self) -> str:
        """Generate a new key for storing data in the storage.

        Returns:
            str: A new key.
        """
        return f"http:{token_hex(self.key_length)}"

    def _get_lock_key(self, session_id: str) -> str:
        """Get lock key.

        Args:
            session_id (str): session id

        Returns:
            str: lock key
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

        Args:
            uid (int): user id
            settings (Settings): app settings
            extra_data (dict | None): Additional data to include\
                in the session, defaults to None.

        Returns:
            str: session id
        """

    async def get_user_id(
        self: Self,
        settings: Settings,
        session_key: str,
        user_agent: str,
        ip: str,
    ) -> int:
        """Get user from storage.

        Args:
            settings (Settings): app settings
            session_key (str): session key
            user_agent (str): user agent
            ip (str): ip address

        Returns:
            int: user id.

        Raises:
            KeyError: key error.
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
        """Set data.

        Args:
            uid (int): uid
            settings (Settings): Settings with database dsn.
            extra_data (dict | None): additional data

        Returns:
            tuple[str, str, dict]: A tuple containing the session_id,\
                signature, and session data dictionary.
        """
        if extra_data is None:
            extra_data = {}

        session_id = self._generate_key()
        signature = self._sign(session_id, settings)

        data = {"id": uid, "sign": signature} | extra_data
        data["issued"] = datetime.now(UTC).isoformat()
        return session_id, signature, data

    @abstractmethod
    async def check_session(self, session_id: str) -> bool:
        """Check session.

        Args:
            session_id (str): session id

        Returns:
            bool: True if session exists
        """

    @abstractmethod
    async def create_ldap_session(
        self: Self,
        uid: int,
        key: str,
        data: dict,
    ) -> None:
        """Create ldap session.

        Args:
            uid (int): user id
            key (str): key
            data (dict): data, defaults to None
        """

    @abstractmethod
    async def check_rekey(self, session_id: str, rekey_interval: int) -> bool:
        """Check rekey.

        Args:
            session_id (str): session id
            rekey_interval (int): rekey interval in seconds

        Returns:
            bool: True if rekey is needed
        """

    @abstractmethod
    async def rekey_session(self, session_id: str, settings: Settings) -> str:
        """Rekey session.

        Args:
            session_id (str): session id
            settings (Settings): app settings

        Returns:
            str: jwt token
        """


class RedisSessionStorage(SessionStorage):
    """Session storage for Session.

    ## Session Structure:

    1. Individual Sessions:
        - Keys:
            - `http:<session_id>`
            - `ldap:<session_id>`
        - Values are JSON-encoded strings with the following structure:
        ```
        {
            "id": <user_id>,
            "ip": <ip>,
            "sign": <sign>,
            "issued": <issued_timestamp>,
            ...
        }
        ```

    2. Mapping User ID to Sessions:
        - Keys:
            - `keys:http:<user_id>`
            - `keys:ldap:<user_id>`
        - Values are Sets containing session keys for the given user ID:
        ```
        Set("http:session_id_1", "ldap:session_id_2", ...)
        ```

    3. Mapping IP to Sessions:
        - Keys:
            - `ip:http:<ip>`
            - `ip:ldap:<ip>`
        - Values are Sets containing session keys associated with the given IP:
        ```
        Set("http:session_id_1", "ldap:session_id_2", ...)
        ```

    4. ZSET for User Sessions:
        - Key:
            - `sessions:http`
            - `sessions:ldap`

    ## Set methods:

    - sadd(key, *values): Add one or more members to a set.
    - srem(key, *values): Remove one or more members from a set.
    - smembers(key): Get all the members in a set.
    """

    def __init__(self, storage: Redis, key_length: int, key_ttl: int) -> None:
        """Initialize the storage.

        Args:
            storage (Redis): The Redis/DragonflyDB instance to use for
                storage.
            key_length (int): The length of the keys to generate.
            key_ttl (int): The time-to-live for keys in seconds.
        """
        self._storage = storage
        self.key_length = key_length
        self.key_ttl = key_ttl

    async def _get_lock(self, name: str, blocking_timeout: int = 5) -> Lock:
        """Get lock.

        Args:
            name (str): lock name
            blocking_timeout (int): blocking timeout, defaults to 5

        Returns:
            Lock: lock object
        """
        return self._storage.lock(
            name=self._get_lock_key(name),
            blocking_timeout=blocking_timeout,
        )

    async def get(self, key: str) -> dict:
        """Retrieve data associated with the given key from storage.

        Args:
            key (str): The key to look up in the storage.

        Returns:
            dict: The data associated with the key, or an empty
            dictionary if the key is not found.

        Raises:
            KeyError: If the key is not found in the storage.
        """
        data = await self._storage.get(key)
        if data is None:
            raise KeyError
        return json.loads(data)

    async def delete(self, keys: Iterable[str]) -> None:
        """Delete data associated with the given key from storage.

        Args:
            keys (Iterable[str]): The keys to delete from the storage.
        """
        await self._storage.delete(*keys)

    async def _fetch_keys(self, key: str) -> set[str]:
        """Fetch keys.

        Args:
            key (str): key

        Returns:
            set[str]: A set of decoded keys from the storage.
        """
        encoded_keys = await self._storage.smembers(key)  # type: ignore
        return {k.decode() for k in encoded_keys}

    async def _get_session_keys_by_ip(
        self,
        ip: str,
        protocol: ProtocolType | None = None,
    ) -> set[str]:
        """Get session keys by ip.

        Retrieves session keys associated with the given IP address. If a
        specific protocol is provided, only sessions for that protocol are
        returned.

        Args:
            ip (str): ip
            protocol (ProtocolType | None): protocol

        Returns:
            set[str]: session keys
        """
        if protocol:
            return await self._fetch_keys(
                self._get_ip_session_key(ip, protocol),
            )

        return (
            await self._fetch_keys(self._get_ip_session_key(ip, "http"))
        ).union(await self._fetch_keys(self._get_ip_session_key(ip, "ldap")))

    async def _get_session_keys_by_uid(
        self,
        uid: int,
        protocol: ProtocolType | None = None,
    ) -> set[str]:
        """Get sesssion keys by user id.

        Retrieves session keys associated with the given User ID. If a
        specific protocol is provided, only sessions for that protocol are
        returned.

        Args:
            uid (int): user id
            protocol (ProtocolType | None): protocol

        Returns:
            set[str]: session keys
        """
        if protocol:
            return await self._fetch_keys(
                self._get_user_session_key(uid, protocol),
            )

        return (
            await self._fetch_keys(self._get_user_session_key(uid, "http"))
        ).union(
            await self._fetch_keys(self._get_user_session_key(uid, "ldap"))
        )

    async def _get_sessions(self, keys: set[str], id_value: str | int) -> dict:
        """Get sessions data by keys.

        Fetches session data from storage for a given set of
        session keys. If a session key exists in storage, its data is loaded
        from JSON. If a session key starts with `ldap:`, the session is marked
        as belonging to the LDAP protocol.

        If a session key does not exist in storage (i.e., the session has
        expired or was manually removed), it is considered an expired session,
        and its reference is removed from the corresponding UID or IP set.

        ## Process:
        1. Fetch session data for each key.
        2. Parse JSON data for each valid session.
        3. Identify expired sessions (i.e., keys that return `None`)
        4. Remove expired session keys from the sets that track user ID
            or IP sessions.

        Args:
            keys (set[str]): session keys
            id_value (str | int): user id or ip

        Returns:
            dict: user sessions contents
        """
        if not keys:
            return {}

        data = await self._storage.mget(*keys)
        retval = {}
        key_sessions_map = defaultdict(list)
        for k, v in zip(keys, data):
            if v is not None:
                tmp = json.loads(v)
                if k.startswith("ldap:"):
                    tmp["protocol"] = "ldap"
                retval[k] = tmp
                continue

            protocol = self._get_protocol(k)

            sessions_key = (
                self._get_user_session_key(id_value, protocol)
                if isinstance(id_value, int)
                else self._get_ip_session_key(id_value, protocol)
            )
            key_sessions_map[sessions_key].append(k)

        if key_sessions_map:
            async with self._storage.pipeline() as pipe:
                for key, expired_sessions in key_sessions_map.items():
                    await pipe.srem(key, *expired_sessions)  # type: ignore
                await pipe.execute()

        return retval

    async def get_user_sessions(
        self,
        uid: int,
        protocol: ProtocolType | None = None,
    ) -> dict:
        """Get sessions by user id.

        Args:
            uid (int): user id
            protocol (ProtocolType | None): protocol

        Returns:
            dict: user sessions contents
        """
        keys = await self._get_session_keys_by_uid(uid, protocol)
        return await self._get_sessions(keys, uid)

    async def get_ip_sessions(
        self,
        ip: str,
        protocol: ProtocolType | None = None,
    ) -> dict:
        """Get sessions data by ip.

        Args:
            ip (str): ip
            protocol (ProtocolType | None): protocol

        Returns:
            dict: user sessions contents
        """
        keys = await self._get_session_keys_by_ip(ip, protocol)
        return await self._get_sessions(keys, ip)

    async def clear_user_sessions(self, uid: int) -> None:
        """Clear user sessions.

        Retrieves all session keys linked to a given user ID,
        removes them from storage, and ensures that any session references
        associated with the user's IP addresses are also cleared.

        ## Process:
        1. Retrieve all session keys linked to the user ID.
        2. Fetch session data from storage using `mget`.
        3. Create a mapping of IP-based session tracking keys to sessions.
        4. Identify and remove session references stored under IP-based keys.
        5. Identify and remove session references stored under UID-based keys.
        6. Delete all user session keys from storage.

        Args:
            uid (int): user id
        """
        keys = await self._get_session_keys_by_uid(uid)
        if not keys:
            return
        data = await self._storage.mget(*keys)

        key_sessions_map = defaultdict(list)
        for k, v in zip(keys, data):
            if v is not None:
                protocol = self._get_protocol(k)
                ip = json.loads(v).get("ip")
                if ip:
                    key_sessions_map[
                        self._get_ip_session_key(ip, protocol)
                    ].append(k)

        http_sessions_key = self._get_user_session_key(uid, "http")
        ldap_sessions_key = self._get_user_session_key(uid, "ldap")

        async with self._storage.pipeline() as pipe:
            for key, sessions in key_sessions_map.items():
                if sessions:
                    await pipe.srem(key, *sessions)  # type: ignore

            await pipe.zrem(self.ZSET_HTTP_SESSIONS, http_sessions_key)
            await pipe.zrem(self.ZSET_LDAP_SESSIONS, ldap_sessions_key)
            await pipe.delete(*keys, http_sessions_key, ldap_sessions_key)
            await pipe.execute()

    async def delete_user_session(self, session_id: str) -> None:
        """Delete user session.

        Removes a session from storage based on the given
        `session_id`.It also ensures that the session is unlinked from the
        user's session list and the associated IP-based session tracking.

        ## Process:
        1. Retrieve session data using the `session_id`.
        2. If the session does not exist, exit the function.
        3. Extract the user ID (`uid`) and IP address (`ip`) from the session
            data.
        5. Determine the protocol type (`http` or `ldap`) from the `session_id`
        7. Acquire a lock to ensure atomicity of session deletion.
        8. Remove the session ID from:
           - The user's session tracking set.
           - The IP-based session tracking set.
        9. Delete the session data from storage.
        10. Release the lock.

        Args:
            session_id (str): session id

        Raises:
            KeyError: key error.
        """
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
        zset_key = (
            self.ZSET_HTTP_SESSIONS
            if protocol == "http"
            else self.ZSET_LDAP_SESSIONS
        )
        async with self._storage.pipeline() as pipe:
            await pipe.srem(sessions_key, session_id)  # type: ignore
            await pipe.srem(ip_key, session_id)  # type: ignore
            await pipe.delete(session_id)
            await pipe.execute()

        if not await self._storage.smembers(sessions_key):  # type: ignore
            await self._storage.zrem(zset_key, sessions_key)

    async def _add_session(
        self,
        session_id: str,
        data: dict,
        uid: int,
        ip_session_key: str | None,
        sessions_key: str,
        ttl: int | None = None,
    ) -> None:
        """Add session.

        Adds a session to the storage and updates the session tracking keys
        for both user ID and IP address.

        Args:
            session_id (str): session id
            data (dict): session data
            uid (int): user id
            ip_session_key (str): ip session key
            sessions_key (str): sessions key
            ttl (int | None): time to live, defaults to None
        """
        zset_key = (
            self.ZSET_HTTP_SESSIONS
            if session_id.startswith("http:")
            else self.ZSET_LDAP_SESSIONS
        )

        async with self._storage.pipeline() as pipe:
            await pipe.set(session_id, json.dumps(data), ex=ttl)
            await pipe.sadd(sessions_key, session_id)  # type: ignore
            if ip_session_key:
                await pipe.sadd(ip_session_key, session_id)  # type: ignore
            await pipe.zadd(
                zset_key,
                {sessions_key: uid},
                nx=True,
            )
            await pipe.execute()

    async def create_session(
        self: Self,
        uid: int,
        settings: Settings,
        *,
        extra_data: dict | None = None,
    ) -> str:
        """Create jwt token.

        Generates a new session for the given user ID (`uid`), stores it
        in storage, and maintains references in session tracking keys.

        ## Process:
        1. Generate a unique session ID and signature, along with session data.
        2. Create a key (`http:<session_id>`) to store session details.
        3. Link the session to the user's session tracking key
            (`keys:http:<uid>`).
        4. If an IP address is provided in `extra_data`, also link the session
            to the IP-based session tracking key (`ip:http:<ip>`).

        Args:
            uid (int): user id
            settings (Settings): settings
            extra_data (dict): extra data

        Returns:
            str: jwt token
        """
        session_id, signature, data = self._generate_session_data(
            uid=uid,
            settings=settings,
            extra_data=extra_data,
        )
        http_sessions_key = self._get_user_session_key(uid, "http")

        ip_sessions_key = None
        if extra_data and (ip := extra_data.get("ip")):
            ip_sessions_key = self._get_ip_session_key(ip, "http")

        await self._add_session(
            session_id,
            data,
            uid,
            ip_sessions_key,
            http_sessions_key,
            self.key_ttl,
        )

        return f"{session_id}.{signature}"

    async def check_session(self, session_id: str) -> bool:
        """Check session.

        Args:
            session_id (str): session id

        Returns:
            bool: True if exists.
        """
        return await self._storage.exists(session_id)

    async def create_ldap_session(
        self,
        uid: int,
        key: str,
        data: dict,
    ) -> None:
        """Create ldap session.

        Generates a new session for the given user ID (`uid`),
        stores it in storage, and maintains references in session tracking
            keys.

        ## Process:
        1. Generate a unique session ID and signature, along with session data.
        2. Create a key (`ldap:<session_id>`) to store session details.
        3. Link the session to the user's session tracking key
            (`keys:ldap:<uid>`).
        4. If an IP address is provided in `extra_data`, also link the session
           to the IP-based session tracking key (`ip:ldap:<ip>`).

        Args:
            uid (int): user id
            key (str): The session key to use for storing the LDAP session.
                This is the unique identifier for the LDAP session in storage.
            data (dict): any data
        """
        data["issued"] = datetime.now(UTC).isoformat()
        ldap_sessions_key = self._get_user_session_key(uid, "ldap")

        ip_sessions_key = None
        if data and (ip := data.get("ip")):
            ip_sessions_key = self._get_ip_session_key(ip, "ldap")

        await self._add_session(
            key,
            data,
            uid,
            ip_sessions_key,
            ldap_sessions_key,
        )

    async def check_rekey(self, session_id: str, rekey_interval: int) -> bool:
        """Check rekey.

        Args:
            session_id (str): session id
            rekey_interval (int): rekey interval in seconds

        Returns:
            bool: True if rekey is needed
        """
        lock = await self._get_lock(session_id)

        if await lock.locked():
            return False

        data = await self.get(session_id)

        issued = datetime.fromisoformat(data.get("issued"))  # type: ignore
        return (datetime.now(UTC) - issued).seconds > rekey_interval

    async def _rekey_session(self, session_id: str, settings: Settings) -> str:
        """Rekey session.

        Rekey an existing session by creating a new
        session ID while preserving the associated user data and expiration
            time.
        The old session is then removed, and the new session is stored.

        ## Process:
        1. Retrieve the session data using `session_id`.
        2. Extract the user ID (`uid`) and IP address (`ip`).
        4. Get the remaining TTL of the current session.
        5. Generate a new session ID and signature while keeping the existing
            session data.
        6. Store the new session with the same TTL.
        7. Add the new session ID to:
           - The user's session tracking key (`keys:http:<uid>`)
           - The IP-based session tracking key (`ip:http:<ip>`)
        8. Delete the old session.

        Args:
            session_id (str): session id
            settings (Settings): app settings

        Returns:
            str: jwt token

        Raises:
            KeyError: key error.
        """
        data = await self.get(session_id)

        uid = data.get("id")
        ip = data.get("ip")
        if uid is None or ip is None:
            raise KeyError("Invalid session id")
        uid = int(uid)

        ttl = await self._storage.ttl(session_id)
        extra_data = data.copy()
        extra_data.pop("sign", None)

        new_session_id, new_signature, new_data = self._generate_session_data(
            uid=uid,
            settings=settings,
            extra_data=extra_data,
        )
        http_sessions_key = self._get_user_session_key(uid, "http")
        ip_sessions_key = self._get_ip_session_key(ip, "http")

        await self._add_session(
            new_session_id,
            new_data,
            uid,
            ip_sessions_key,
            http_sessions_key,
            ttl,
        )

        await self.delete_user_session(session_id)

        return f"{new_session_id}.{new_signature}"

    async def rekey_session(self, session_id: str, settings: Settings) -> str:
        """Rekey session.

        Args:
            session_id (str): session id
            settings (Settings): app settings

        Returns:
            str: jwt token
        """
        lock = await self._get_lock(session_id)

        async with lock:
            return await self._rekey_session(session_id, settings)
