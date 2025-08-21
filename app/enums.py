"""Enums.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enum import IntEnum, StrEnum


class AceType(IntEnum):
    """ACE types."""

    CREATE_CHILD = 1
    READ = 2
    WRITE = 3
    DELETE = 4
    PASSWORD_MODIFY = 5


class RoleScope(IntEnum):
    """Scope of the role."""

    BASE_OBJECT = 0
    SINGLE_LEVEL = 1
    WHOLE_SUBTREE = 2


class MFAFlags(IntEnum):
    """Two-Factor auth action."""

    DISABLED = 0
    ENABLED = 1
    WHITELIST = 2


class MFAChallengeStatuses(StrEnum):
    """Two-Factor challenge status."""

    BYPASS = "bypass"
    PENDING = "pending"


class KindType(StrEnum):
    """Object kind types."""

    STRUCTURAL = "STRUCTURAL"
    ABSTRACT = "ABSTRACT"
    AUXILIARY = "AUXILIARY"


class AuditSeverity(IntEnum):
    """Audit policy severity."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


class AuditDestinationProtocolType(StrEnum):
    """Audit destination protocol type."""

    UDP = "udp"
    TCP = "tcp"


class AuditDestinationServiceType(StrEnum):
    """Audit destination type."""

    SYSLOG = "syslog"
