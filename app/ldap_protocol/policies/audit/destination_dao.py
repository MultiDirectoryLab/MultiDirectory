"""Audit destination dao module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dataclasses import asdict

from adaptix.conversion import get_converter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_dao import AbstractDAO
from entities import AuditDestination
from enums import ErrorCode
from errors.contracts import ErrorCodeCarrierError

from .dataclasses import AuditDestinationDTO
from .exception import AuditNotFoundError

_convert = get_converter(AuditDestination, AuditDestinationDTO)


class AuditDestinationDAO(AbstractDAO[AuditDestinationDTO, int]):
    """Audit destination DAO class."""

    def __init__(self, session: AsyncSession):
        """Initialize Audit Destination DAO with a database session."""
        self._session = session

    async def _get_raw(self, _id: int) -> AuditDestination:
        destination = await self._session.get(AuditDestination, _id)
        if not destination:
            raise ErrorCodeCarrierError(
                AuditNotFoundError(
                    f"Destination with id {_id} not found.",
                ),
                ErrorCode.AUDIT_NOT_FOUND,
            )
        return destination

    async def get(
        self,
        _id: int,
    ) -> AuditDestinationDTO:
        """Get audit destination by ID."""
        return _convert(await self._get_raw(_id))

    async def get_all(self) -> list[AuditDestinationDTO]:
        """Get all audit destinations."""
        return [
            _convert(destination)
            for destination in (
                await self._session.scalars(select(AuditDestination))
            ).all()
        ]

    async def create(
        self,
        dto: AuditDestinationDTO,
    ) -> None:
        """Create a new audit destination."""
        d = asdict(dto)
        del d["id"]
        destination = AuditDestination(**d)
        self._session.add(destination)
        await self._session.flush()

    async def update(
        self,
        _id: int,
        dto: AuditDestinationDTO,
    ) -> None:
        """Update an existing audit destination."""
        existing_destination = await self._get_raw(_id)

        existing_destination.name = dto.name
        existing_destination.service_type = dto.service_type
        existing_destination.host = dto.host
        existing_destination.port = dto.port
        existing_destination.protocol = dto.protocol
        existing_destination.is_enabled = dto.is_enabled

        await self._session.flush()

    async def delete(self, _id: int) -> None:
        """Delete an audit destination."""
        existing_destination = await self._get_raw(_id)
        await self._session.delete(existing_destination)
        await self._session.flush()
