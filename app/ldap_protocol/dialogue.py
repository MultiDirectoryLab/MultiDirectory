"""Codes mapping.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
from secrets import token_hex
from typing import TYPE_CHECKING, AsyncIterator, Iterable, NoReturn, Self

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.policies.network_policy import build_policy_query
from models import NetworkPolicy, User

if TYPE_CHECKING:
    from .messages import LDAPRequestMessage


@dataclass
class UserSchema:
    """User model, alias for db user."""

    id: int  # noqa: A003
    session_id: str
    sam_accout_name: str
    user_principal_name: str
    mail: str | None
    display_name: str | None
    directory_id: int
    dn: str

    access_policies_ids: list[int]
    account_exp: datetime | None

    @classmethod
    async def from_db(
        cls,
        user: User,
        session_id: str,
    ) -> "UserSchema":
        """Create model from db model."""
        return cls(
            id=user.id,
            session_id=session_id.split(".")[0],
            sam_accout_name=user.sam_accout_name,
            user_principal_name=user.user_principal_name,
            mail=user.mail,
            display_name=user.display_name,
            directory_id=user.directory_id,
            dn=user.directory.path_dn,
            access_policies_ids=[
                policy.id
                for group in user.groups
                for policy in group.access_policies
            ],
            account_exp=user.account_exp,
        )


class LDAPSession:
    """LDAPSession for one client handling."""

    ip: IPv4Address | IPv6Address
    policy: NetworkPolicy | None

    def __init__(
        self, *, user: UserSchema | None = None,
        storage: SessionStorage | None = None,
    ) -> None:
        """Set lock."""
        self._lock = asyncio.Lock()
        self._user: UserSchema | None = user
        self.queue: asyncio.Queue["LDAPRequestMessage"] = asyncio.Queue()
        self.id = uuid.uuid4()
        self.storage = storage

    def __str__(self) -> str:
        """Session with id."""
        return f"LDAPSession({self.id})"

    @property
    def user(self) -> UserSchema | None:
        """User getter, not implemented."""
        return self._user

    @user.setter
    def user(self, user: User) -> None:
        raise NotImplementedError(
            "Cannot manually set user, use `set_user()` instead",
        )

    async def set_user(self, user: User | UserSchema) -> None:
        """Bind user to session concurrently save."""
        async with self._lock:
            if isinstance(user, User):
                self._user = await UserSchema.from_db(user, '')
            else:
                self._user = user

    async def delete_user(self) -> None:
        """Unbind user from session concurrently save."""
        async with self._lock:
            self._user = None

    async def get_user(self) -> UserSchema | None:
        """Get user from session concurrently save."""
        async with self._lock:
            return self._user

    @asynccontextmanager
    async def lock(self) -> AsyncIterator[UserSchema | None]:
        """Lock session, user cannot be deleted or get while lock is set."""
        async with self._lock:
            yield self._user

    @staticmethod
    def get_address(writer: asyncio.StreamWriter) -> str:
        """Get client address."""
        return ":".join(map(str, writer.get_extra_info("peername")))

    async def get_ip(
            self, writer: asyncio.StreamWriter) -> IPv4Address | IPv6Address:
        """Get ip addr from writer."""
        addr = self.get_address(writer)
        ip = ip_address(addr.split(":")[0])
        self.ip = ip
        return ip

    @staticmethod
    async def _get_policy(
        ip: IPv4Address, session: AsyncSession,
    ) -> NetworkPolicy | None:
        query = build_policy_query(ip, "is_ldap")
        return await session.scalar(query)

    async def validate_conn(
        self, ip: IPv4Address | IPv6Address, session: AsyncSession,
    ) -> None:
        """Validate network policies."""
        policy = await self._get_policy(ip, session)  # type: ignore
        if policy is not None:
            self.policy = policy
            await self.bind_session()
            return

        raise PermissionError

    @property
    def key(self) -> str:
        """Get key."""
        return f"ldap:{self.id}"

    async def bind_session(self) -> None:
        """Bind session to storage."""
        if self.storage is None or self.user is None:
            return

        await self.storage.set_data(
            self.key,
            self.user.__dict__ | {"ip": str(self.ip)},
            expire=None,
        )
        await self.storage.append_session(
            self.storage.get_id_hash(self.user.id),
            self.key,
        )

    async def disconnect(self) -> None:
        """Disconnect session."""
        if self.storage is None or self.user is None:
            return  # type: ignore

        await self.storage.delete([self.key])
        await self.storage.delete_user_session(self.user)

    async def ensure_session_exists(self) -> NoReturn:
        """Ensure session exists in storage."""
        if self.storage is None:
            raise AttributeError("Storage is not set")

        while True:
            if not await self.storage.check_session(self.key):
                raise ConnectionAbortedError("Session missing in storage")
            await asyncio.sleep(30)


class SessionStorage:
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

    def generate_key(self) -> str:
        """Generate a new key for storing data in the storage.

        :return str: A new key.
        """
        return token_hex(self.key_length)

    async def get_n_rows(self, offset: int, limit: int) -> dict[str, dict]:
        """Retrieve a batch of data from storage.

        :param int offset: The offset to start retrieving rows from.
        :param int limit: The limit of rows to retrieve.
        :return dict[str, dict]:
            A list of key-data pairs for the retrieved rows.
        """
        batch: dict[str, dict] = {}

        cursor, keys = await self._storage.scan(cursor=offset, count=limit)

        if cursor == 0:
            return batch

        async for key in keys:
            data = await self._storage.get(key)
            if data is not None:
                batch[key] = json.loads(data)
        return batch

    async def set_data(self, key: str, data: dict, expire: int | None) -> None:
        """Store data associated with the given key in storage.

        :param str key: The key to store the data under.
        :param dict data: The data to store.
        """
        await self._storage.set(key, json.dumps(data), ex=expire)

    async def delete(self, keys: Iterable[str]) -> None:
        """Delete data associated with the given key from storage.

        :param str key: The key to delete from the storage.
        """
        await self._storage.delete(*keys)

    async def get_user_data(self, user: UserSchema) -> dict:
        """Get user data from storage.

        :param UserSchema user: The user to get data for.
        :return dict: The data associated with the user.
        """
        return await self.get(user.session_id)

    def get_id_hash(self, user_id: int) -> str:
        """Get user id hash."""
        return hashlib.blake2b(
            str(user_id).encode(), digest_size=16).hexdigest()

    async def get_user_sessions(self, user: UserSchema | int) -> set[str]:
        """Get user sessions."""
        if isinstance(user, UserSchema):
            uid = user.id

        keys = await self._storage.get(self.get_id_hash(uid))
        return set(keys.split(b";"))

    async def clear_user_sessions(self, user: UserSchema | int) -> None:
        """Clear user sessions."""
        keys = await self.get_user_sessions(user)
        await self.delete(keys)
        uid = user if isinstance(user, int) else user.id
        await self._storage.delete(self.get_id_hash(uid))

    async def delete_user_session(self, user: UserSchema) -> None:
        """Delete user session."""
        keys = await self.get_user_sessions(user)
        keys.remove(user.session_id)

        await self._storage.set(
            self.get_id_hash(user.id),
            ";".join(keys),
            keepttl=True,
        )

    async def update_user_data(self, user: UserSchema, data: dict) -> None:
        """Set user data in storage.

        :param UserSchema user: The user to set data for.
        :param dict data: The data to set for the user.
        """
        dbdata = await self.get(user.session_id)
        await self._storage.set(user.session_id, json.dumps(dbdata | data))

    @staticmethod
    def _sign(session_id: str, settings: Settings) -> str:
        """Sign session id."""
        return hmac.new(
            settings.SECRET_KEY.encode(),
            session_id.encode(),
            hashlib.sha256,
        ).hexdigest()

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

        session_id = self.generate_key()
        signature = self._sign(session_id, settings)

        data = {"id": uid, "sign": signature} | extra_data
        data['issued'] = datetime.now(timezone.utc).isoformat()

        await self._storage.set(session_id, json.dumps(data), ex=self.key_ttl)
        await self.append_session(self.get_id_hash(uid), session_id)

        return f"{session_id}.{signature}"

    async def append_session(self, key: str, session_id: str) -> None:
        """Append session to user sessions."""
        await self._storage.append(key, f"{session_id};")

    async def get_user_id(
        self: Self,
        settings: Settings,
        session_key: str,
    ) -> int:
        """Get user from storage.

        :param Settings settings: app settings
        :raises KeyError: missing key
        :return int: user id from storage
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

    async def check_session(self, session_id: str) -> bool:
        """Check session."""
        return await self._storage.exists(session_id)
