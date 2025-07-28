"""Audit destination dao module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import (
    AuditDestination,
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
)

from .exception import AuditNotFoundError


class AuditDestinationDAO:
    """Audit destination DAO class."""

    def __init__(self, session: AsyncSession):
        """Initialize Audit Destination DAO with a database session."""
        self._session = session

    async def get_destination_by_id(
        self,
        destination_id: int,
    ) -> AuditDestination:
        """Get audit destination by ID."""
        destination = await self._session.get(AuditDestination, destination_id)
        if not destination:
            raise AuditNotFoundError(
                f"Destination with id {destination_id} not found."
            )
        return destination

    async def get_destinations(self) -> list[AuditDestination]:
        """Get all audit destinations."""
        return list(
            (await self._session.scalars(select(AuditDestination))).all()
        )

    async def create_destination(
        self,
        name: str,
        service_type: AuditDestinationServiceType,
        host: str,
        port: int,
        protocol: AuditDestinationProtocolType,
        is_enabled: bool = False,
    ) -> AuditDestination:
        """Create a new audit destination."""
        destination = AuditDestination(
            name=name,
            service_type=service_type,
            host=host,
            port=port,
            protocol=protocol,
            is_enabled=is_enabled,
        )
        self._session.add(destination)
        await self._session.flush()
        return destination

    async def update_destination(
        self,
        destination: AuditDestination,
        name: str,
        service_type: AuditDestinationServiceType,
        host: str,
        port: int,
        protocol: AuditDestinationProtocolType,
        is_enabled: bool,
    ) -> None:
        """Update an existing audit destination."""
        destination.name = name
        destination.service_type = service_type
        destination.host = host
        destination.port = port
        destination.protocol = protocol
        destination.is_enabled = is_enabled
        await self._session.flush()

    async def delete_destination(self, destination: AuditDestination) -> None:
        """Delete an audit destination."""
        await self._session.delete(destination)
        await self._session.flush()
