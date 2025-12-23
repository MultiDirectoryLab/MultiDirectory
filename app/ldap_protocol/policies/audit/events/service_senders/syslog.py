"""Syslog sender.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from copy import deepcopy
from typing import Any

from loguru import logger

from enums import AuditDestinationProtocolType, AuditDestinationServiceType
from ldap_protocol.policies.audit.events.dataclasses import (
    NormalizedAuditEvent,
)

from .base import AuditDestinationSenderABC
from .rfc5424_serializer import RFC5424Serializer


class SyslogSender(AuditDestinationSenderABC):
    """Syslog sender with RFC 5424 support.

    Sends audit events to syslog servers using RFC 5424 format.
    Supports both TCP and UDP protocols.
    """

    service_name: AuditDestinationServiceType = (
        AuditDestinationServiceType.SYSLOG
    )
    DEFAULT_TIMEOUT: int = 10
    SYSLOG_VERSION: int = 1

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize syslog sender with RFC 5424 serializer."""
        super().__init__(*args, **kwargs)
        self.__rfc_serializer = RFC5424Serializer(
            app_name=self.DEFAULT_APP_NAME,
            facility="authpriv",
        )

    async def _send_udp(self, message: str) -> None:
        """Send UDP."""
        transport, _ = await asyncio.wait_for(
            asyncio.get_event_loop().create_datagram_endpoint(
                lambda: asyncio.DatagramProtocol(),
                remote_addr=(self._destination.host, self._destination.port),
            ),
            timeout=self.DEFAULT_TIMEOUT,
        )
        transport.sendto(message.encode("utf-8"))
        transport.close()

    async def _send_tcp(self, message: str) -> None:
        """Send TCP."""
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=self._destination.host,
                port=self._destination.port,
            ),
            timeout=self.DEFAULT_TIMEOUT,
        )

        writer.write(message.encode("utf-8"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def send(self, event: NormalizedAuditEvent) -> None:
        """Send event."""
        structured_data = deepcopy(event.destination_dict)

        syslog_message = self.__rfc_serializer.serialize(
            event=event,
            structured_data=structured_data,
            syslog_version=self.SYSLOG_VERSION,
        )

        if self._destination.protocol == AuditDestinationProtocolType.UDP:
            callback = self._send_udp
        elif self._destination.protocol == AuditDestinationProtocolType.TCP:
            callback = self._send_tcp
        else:
            raise ValueError(
                f"Unsupported protocol: {self._destination.protocol}",
            )

        try:
            await callback(syslog_message)
        except TimeoutError as te:
            logger.error(
                f"Timeout during syslog {self._destination.name} send: {te}",
            )
            raise
        except (OSError, ConnectionRefusedError, ConnectionError) as ce:
            logger.error(
                f"Failed to send syslog {self._destination.name}: {ce}",
            )
            raise
        except Exception as e:
            logger.error(
                f"Error during syslog {self._destination.name} send: {e}",
            )
            raise
