"""Codes mapping."""

import asyncio
from enum import Enum

from models.ldap3 import User


class Operation(int, Enum):
    """Changes enum for modify request."""

    ADD = 0
    DELETE = 1
    REPLACE = 2


class LDAPCodes(int, Enum):
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


class Session:
    """Session for one client handling."""

    def __init__(self) -> None:
        """Set lock."""
        self.lock = asyncio.Lock()

    user: User | None = None

    async def set_user(self, user: User):
        """Bind user to session concurrently save."""
        async with self.lock:
            self.user = user

    async def delete_user(self):
        """Unbind user from session concurrently save."""
        async with self.lock:
            self.user = None

    async def get_user(self):
        """Get user from session concurrently save."""
        async with self.lock:
            return self.user
