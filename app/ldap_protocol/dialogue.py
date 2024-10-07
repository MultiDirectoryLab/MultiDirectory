"""Codes mapping.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from ipaddress import IPv4Address, ip_address
from typing import TYPE_CHECKING, AsyncIterator, Literal

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from models import NetworkPolicy, User

if TYPE_CHECKING:
    from .messages import LDAPRequestMessage


class Operation(IntEnum):
    """Changes enum for modify request."""

    ADD = 0
    DELETE = 1
    REPLACE = 2


@dataclass
class UserSchema:
    """User model, alias for db user."""

    id: int  # noqa: A003
    sam_accout_name: str
    user_principal_name: str
    mail: str
    display_name: str
    directory_id: int
    dn: str

    access_policies_ids: list[int]
    access_type: Literal['access', 'refresh', 'multifactor']
    exp: int
    account_exp: datetime | None

    @classmethod
    def from_db(
        cls,
        user: User,
        access: Literal['access', 'refresh', 'multifactor'],
        exp: int = 0,
    ) -> 'UserSchema':
        """Create model from db model."""
        return cls(
            id=user.id,
            sam_accout_name=user.sam_accout_name,
            user_principal_name=user.user_principal_name,
            mail=user.mail,
            display_name=user.display_name,
            access_type=access,
            exp=exp,
            directory_id=user.directory_id,
            dn=user.directory.path_dn,
            access_policies_ids=[
                policy.id for group in user.groups
                for policy in group.access_policies],
            account_exp=user.account_exp,
        )


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
    policy: NetworkPolicy | None

    def __init__(self, *, user: UserSchema | None = None) -> None:
        """Set lock."""
        self._lock = asyncio.Lock()
        self._user: UserSchema | None = user
        self.queue: asyncio.Queue['LDAPRequestMessage'] = asyncio.Queue()
        self.id = uuid.uuid4()

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
            'Cannot manually set user, use `set_user()` instead')

    async def set_user(self, user: User | UserSchema) -> None:
        """Bind user to session concurrently save."""
        async with self._lock:
            if isinstance(user, User):
                self._user = UserSchema.from_db(user, access='access')
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
        return ':'.join(map(str, writer.get_extra_info('peername')))

    async def get_ip(self, writer: asyncio.StreamWriter) -> IPv4Address:
        """Get ip addr from writer."""
        addr = self.get_address(writer)
        return ip_address(addr.split(':')[0])  # type: ignore

    @staticmethod
    async def _get_policy(
            ip: IPv4Address, session: AsyncSession) -> NetworkPolicy | None:
        return await session.scalar((  # noqa
            select(NetworkPolicy)
            .filter_by(enabled=True)
            .options(selectinload(NetworkPolicy.groups))
            .filter(
                text(':ip <<= ANY("Policies".netmasks)').bindparams(ip=ip))
            .order_by(NetworkPolicy.priority.asc())
            .limit(1)
        ))

    async def validate_conn(
            self, ip: IPv4Address, session: AsyncSession) -> None:
        """Validate network policies."""
        policy = await self._get_policy(ip, session)
        if policy is not None:
            self.policy = policy
            return

        raise PermissionError
