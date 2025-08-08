"""Abstract audit destination sender service.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod

from ldap_protocol.policies.audit.dataclasses import AuditDestinationDTO
from ldap_protocol.policies.audit.enums import AuditDestinationServiceType
from ldap_protocol.policies.audit.events.dataclasses import (
    NormalizedAuditEvent,
)


class AuditDestinationSenderABC(ABC):
    """Senders abstract base class."""

    _destination: AuditDestinationDTO
    DEFAULT_APP_NAME: str = "MultiDirectory"

    def __init__(self, destination: AuditDestinationDTO) -> None:
        """Initialize SendersABC."""
        self._destination = destination

    @abstractmethod
    async def send(self, event: NormalizedAuditEvent) -> None:
        """Send event."""

    @property
    @abstractmethod
    def service_name(self) -> AuditDestinationServiceType:
        """Get service name."""
