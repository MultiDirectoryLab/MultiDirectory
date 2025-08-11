"""Senders map.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ldap_protocol.policies.audit.enums import AuditDestinationServiceType

from .base import AuditDestinationSenderABC
from .syslog import SyslogSender

senders: dict[AuditDestinationServiceType, type[AuditDestinationSenderABC]] = {
    AuditDestinationServiceType.SYSLOG: SyslogSender,
}

__all__ = ["senders"]
