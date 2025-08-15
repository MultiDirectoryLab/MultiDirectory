"""Senders map.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from enums import AuditDestinationServiceType

from .base import AuditDestinationSenderABC
from .syslog import SyslogSender

senders: dict[AuditDestinationServiceType, type[AuditDestinationSenderABC]] = {
    AuditDestinationServiceType.SYSLOG: SyslogSender,
}

__all__ = ["senders"]
