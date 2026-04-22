"""RID Manager gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Attribute, Directory
from ldap_protocol.rid_manager.exceptions import RIDManagerAvailablePoolNotFoundError, RIDManagerNotFoundError
from ldap_protocol.rid_manager.types import HostMachineShortName
from repo.pg.tables import queryable_attr as qa


class RIDManagerGateway:
    """RID Manager gateway."""

    def __init__(self, session: AsyncSession, host_machine_short_name: HostMachineShortName) -> None:
        """Initialize RID Manager gateway."""
        self._session = session
        self._host_machine_short_name = host_machine_short_name

    async def get_rid_manager(self) -> Directory:
        """Get RID Manager directory."""
        rid_manager = await self._session.scalar(select(Directory).where(qa(Directory.name) == "RID Manager$"))
        if not rid_manager:
            raise RIDManagerNotFoundError("RID Manager directory not found")
        return rid_manager

    async def get_rid_available_pool(self) -> int:
        """Get RID available pool."""
        rid_available_pool = await self._session.scalar(
            select(Attribute).where(qa(Attribute.name) == "rIDAvailablePool").with_for_update()
        )
        if not (rid_available_pool and rid_available_pool.value):
            raise RIDManagerAvailablePoolNotFoundError("RID available pool not found")
        return int(rid_available_pool.value)

    async def update_rid_available_pool(self, available_pool: int) -> None:
        """Update RID available pool."""
        await self._session.execute(
            update(Attribute).where(qa(Attribute.name) == "rIDAvailablePool").values(value=str(available_pool))
        )
