"""Codes mapping.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from contextlib import asynccontextmanager
from enum import IntEnum
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, AsyncIterator

import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import Settings
from models.ldap3 import NetworkPolicy, User

if TYPE_CHECKING:
    from .messages import LDAPRequestMessage


class Operation(IntEnum):
    """Changes enum for modify request."""

    ADD = 0
    DELETE = 1
    REPLACE = 2


class LDAPCodes(IntEnum):
    """LDAP protocol codes mapping.

    SUCCESS = 0
    OPERATIONS_ERROR = 1
    PROTOCOL_ERROR = 2
    TIME_LIMIT_EXCEEDED = 3
    SIZE_LIMIT_EXCEEDED = 4
    COMPARE_FALSE = 5
    COMPARE_TRUE = 6
    AUTH_METHOD_NOT_SUPPORTED = 7
    STRONGER_AUTH_REQUIRED = 8
    # -- 9 reserved --
    REFERRAL = 10
    ADMIN_LIMIT_EXCEEDED = 11
    UNAVAILABLE_CRITICAL_EXTENSION = 12
    CONFIDENTIALITY_REQUIRED = 13
    SASL_BIND_IN_PROGRESS = 14
    NO_SUCH_ATTRIBUTE = 16
    UNDEFINED_ATTRIBUTE_TYPE = 17
    INAPPROPRIATE_MATCHING = 18
    CONSTRAINT_VIOLATION = 19
    ATTRIBUTE_OR_VALUE_EXISTS = 20
    INVALID_ATTRIBUTE_SYNTAX = 21
    # -- 22-31 unused --
    NO_SUCH_OBJECT = 32
    ALIAS_PROBLEM = 33
    INVALID_DN_SYNTAX = 34
    # -- 35 reserved for undefined isLeaf --
    ALIAS_DEREFERENCING_PROBLEM = 36
    # -- 37-47 unused --
    INAPPROPRIATE_AUTHENTICATION = 48
    INVALID_CREDENTIALS = 49
    INSUFFICIENT_ACCESS_RIGHTS = 50
    BUSY = 51
    UNAVAILABLE = 52
    UNWILLING_TO_PERFORM = 53
    LOOP_DETECT = 54
    # -- 55-63 unused --
    NAMING_VIOLATION = 64
    OBJECT_CLASS_VIOLATION = 65
    NOT_ALLOWED_ON_NON_LEAF = 66
    NOT_ALLOWED_ON_RDN = 67
    ENTRY_ALREADY_EXISTS = 68
    OBJECT_CLASS_MODS_PROHIBITED = 69
    # -- 70 reserved for CLDAP --
    AFFECTS_MULTIPLE_DS_AS = 71
    # -- 72-79 unused --
    OTHER = 80
    """

    SUCCESS = 0
    OPERATIONS_ERROR = 1
    PROTOCOL_ERROR = 2
    TIME_LIMIT_EXCEEDED = 3
    SIZE_LIMIT_EXCEEDED = 4
    COMPARE_FALSE = 5
    COMPARE_TRUE = 6
    AUTH_METHOD_NOT_SUPPORTED = 7
    STRONGER_AUTH_REQUIRED = 8
    # -- 9 reserved --
    REFERRAL = 10
    ADMIN_LIMIT_EXCEEDED = 11
    UNAVAILABLE_CRITICAL_EXTENSION = 12
    CONFIDENTIALITY_REQUIRED = 13
    SASL_BIND_IN_PROGRESS = 14
    NO_SUCH_ATTRIBUTE = 16
    UNDEFINED_ATTRIBUTE_TYPE = 17
    INAPPROPRIATE_MATCHING = 18
    CONSTRAINT_VIOLATION = 19
    ATTRIBUTE_OR_VALUE_EXISTS = 20
    INVALID_ATTRIBUTE_SYNTAX = 21
    # -- 22-31 unused --
    NO_SUCH_OBJECT = 32
    ALIAS_PROBLEM = 33
    INVALID_DN_SYNTAX = 34
    # -- 35 reserved for undefined isLeaf --
    ALIAS_DEREFERENCING_PROBLEM = 36
    # -- 37-47 unused --
    INAPPROPRIATE_AUTHENTICATION = 48
    INVALID_CREDENTIALS = 49
    INSUFFICIENT_ACCESS_RIGHTS = 50
    BUSY = 51
    UNAVAILABLE = 52
    UNWILLING_TO_PERFORM = 53
    LOOP_DETECT = 54
    # -- 55-63 unused --
    NAMING_VIOLATION = 64
    OBJECT_CLASS_VIOLATION = 65
    NOT_ALLOWED_ON_NON_LEAF = 66
    NOT_ALLOWED_ON_RDN = 67
    ENTRY_ALREADY_EXISTS = 68
    OBJECT_CLASS_MODS_PROHIBITED = 69
    # -- 70 reserved for CLDAP --
    AFFECTS_MULTIPLE_DS_AS = 71
    # -- 72-79 unused --
    OTHER = 80


class LDAPSession:
    """LDAPSession for one client handling."""

    ip: IPv4Address
    addr: str
    policy: NetworkPolicy | None
    client: httpx.AsyncClient
    settings: Settings

    def __init__(self, *, user: User | None = None) -> None:
        """Set lock."""
        self._lock = asyncio.Lock()
        self._user: User | None = user
        self.queue: asyncio.Queue['LDAPRequestMessage'] = asyncio.Queue()

    @property
    def user(self) -> User | None:
        """User getter, not implemented."""
        return self._user

    @user.setter
    def user(self, user: User) -> None:
        raise NotImplementedError(
            'Cannot manually set user, use `set_user()` instead')

    async def set_user(self, user: User) -> None:
        """Bind user to session concurrently save."""
        async with self._lock:
            self._user = user

    async def delete_user(self) -> None:
        """Unbind user from session concurrently save."""
        async with self._lock:
            self._user = None

    async def get_user(self) -> User:
        """Get user from session concurrently save."""
        async with self._lock:
            return self._user

    @asynccontextmanager
    async def lock(self) -> AsyncIterator[User]:
        """Lock session, user cannot be deleted or get while lock is set."""
        async with self._lock:
            yield self._user

    async def validate_conn(
            self, ip: IPv4Address, session: AsyncSession) -> None:
        """Validate network policies."""
        policy = await session.scalar((  # noqa
            select(NetworkPolicy)
            .filter_by(enabled=True)
            .options(selectinload(NetworkPolicy.groups))
            .filter(
                text(':ip <<= ANY("Policies".netmasks)').bindparams(ip=ip))
            .order_by(NetworkPolicy.priority.asc())
            .limit(1)
        ))
        if policy is not None:
            self.policy = policy
            return

        raise PermissionError
