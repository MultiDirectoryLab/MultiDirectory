"""Codes mapping.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import TYPE_CHECKING, AsyncIterator, NoReturn

import gssapi
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.policies.network_policy import build_policy_query
from models import NetworkPolicy, User

from .session_storage import SessionStorage

if TYPE_CHECKING:
    from ldap_protocol.ldap_requests.bind_methods import GSSAPISL

    from .messages import LDAPRequestMessage


@dataclass
class UserSchema:
    """User model, alias for db user."""

    id: int
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

    gssapi_authenticated: bool = False
    gssapi_security_context: gssapi.SecurityContext | None = None
    gssapi_security_layer: "GSSAPISL"

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
                self._user = await UserSchema.from_db(user, self.key)
                await self.bind_session()
            else:
                self._user = user

    async def delete_user(self) -> None:
        """Unbind user from session concurrently save."""
        await self.disconnect()

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

    def _bound_ip(self) -> bool:
        return hasattr(self, "ip")

    async def bind_session(self) -> None:
        """Bind session to storage."""
        if self.storage is None or self.user is None or not self._bound_ip():
            return

        await self.storage.delete_user_session(self.key)
        await self.storage.create_ldap_session(
            self.user.id, self.key, {"id": self.user.id, "ip": str(self.ip)})

    async def disconnect(self) -> None:
        """Disconnect session."""
        if self.storage is None or self.user is None:
            return
        await self.storage.delete_user_session(self.key)

    async def ensure_session_exists(self) -> NoReturn:
        """Ensure session exists in storage.

        Does nothing if anonymous, wait 30s and if user bound, check it.
        """
        if self.storage is None:
            raise AttributeError("Storage is not set")

        while True:
            await asyncio.sleep(30)

            if not self.user:
                continue

            if not await self.storage.check_session(self.key):
                raise ConnectionAbortedError("Session missing in storage")
