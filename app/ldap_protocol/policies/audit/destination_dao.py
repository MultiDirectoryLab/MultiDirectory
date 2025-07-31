"""Audit destination dao module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import asdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditDestination

from .dataclasses import AuditDestinationDTO
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
                f"Destination with id {destination_id} not found.",
            )
        return destination

    async def get_destinations(self) -> list[AuditDestinationDTO]:
        """Get all audit destinations."""
        return [
            AuditDestinationDTO(
                id=destination.id,
                name=destination.name,
                service_type=destination.service_type,
                host=destination.host,
                port=destination.port,
                protocol=destination.protocol,
                is_enabled=destination.is_enabled,
            )
            for destination in (
                await self._session.scalars(select(AuditDestination))
            ).all()
        ]

    async def create_destination(
        self,
        destination_dto: AuditDestinationDTO,
    ) -> AuditDestinationDTO:
        """Create a new audit destination."""
        destination = AuditDestination(**asdict(destination_dto))
        self._session.add(destination)
        await self._session.flush()
        await self._session.refresh(destination)
        return AuditDestinationDTO(
            id=destination.id,
            name=destination.name,
            service_type=destination.service_type,
            host=destination.host,
            port=destination.port,
            protocol=destination.protocol,
            is_enabled=destination.is_enabled,
        )

    async def update_destination(
        self,
        destination_id: int,
        destination_dto: AuditDestinationDTO,
    ) -> AuditDestinationDTO:
        """Update an existing audit destination."""
        existing_destination = await self.get_destination_by_id(destination_id)

        existing_destination.name = destination_dto.name
        existing_destination.service_type = destination_dto.service_type
        existing_destination.host = destination_dto.host
        existing_destination.port = destination_dto.port
        existing_destination.protocol = destination_dto.protocol
        existing_destination.is_enabled = destination_dto.is_enabled

        await self._session.flush()
        await self._session.refresh(existing_destination)

        return AuditDestinationDTO(
            id=existing_destination.id,
            name=existing_destination.name,
            service_type=existing_destination.service_type,
            host=existing_destination.host,
            port=existing_destination.port,
            protocol=existing_destination.protocol,
            is_enabled=existing_destination.is_enabled,
        )

    async def delete_destination(self, destination_id: int) -> None:
        """Delete an audit destination."""
        existing_destination = await self.get_destination_by_id(destination_id)
        await self._session.delete(existing_destination)
        await self._session.flush()
