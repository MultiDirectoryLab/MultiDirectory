"""RID Set gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Attribute, Directory
from ldap_protocol.rid_manager.dtos import RIDSetAllocationParamsDTO
from ldap_protocol.rid_manager.exceptions import (
    RIDManagerRidAllocationPoolNotFoundError,
    RIDManagerRidNextRIDNotFoundError,
    RIDManagerRidPreviousAllocationPoolNotFoundError,
    RIDManagerRidSetNotFoundError,
)
from repo.pg.tables import queryable_attr as qa


class RIDSetGateway:
    """RID Set gateway."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize RID Set gateway."""
        self._session = session

    async def get(self, domain_controller: Directory) -> Directory:
        """Get RID Set directory."""
        rid_set = await self._session.scalar(
            select(Directory).where(
                qa(Directory.name) == "RID Set",
                qa(Directory.parent_id) == domain_controller.id,
            ),
        )
        if not rid_set:
            raise RIDManagerRidSetNotFoundError("RID Set directory not found")

        return rid_set

    async def add(self, domain_controller: Directory) -> Directory:
        """Add RID Set directory."""
        rid_set_dir = Directory(
            is_system=True,
            name="RID Set",
        )
        rid_set_dir.create_path(domain_controller, "cn")

        self._session.add(rid_set_dir)
        await self._session.flush()

        rid_set_dir.parent_id = domain_controller.id
        await self._session.refresh(rid_set_dir, ["id"])

        self._session.add(
            Attribute(
                name="cn",
                value="RID Set",
                directory_id=rid_set_dir.id,
            ),
        )

        self._session.add(
            Attribute(
                name="objectClass",
                value="top",
                directory_id=rid_set_dir.id,
            ),
        )

        self._session.add(
            Attribute(
                name="objectClass",
                value="rIDSet",
                directory_id=rid_set_dir.id,
            ),
        )

        await self._session.flush()

        await self._session.refresh(
            instance=rid_set_dir,
            attribute_names=["attributes"],
            with_for_update=None,
        )

        return rid_set_dir

    async def set_allocation_attrs(
        self,
        rid_set: Directory,
        allocation_params: RIDSetAllocationParamsDTO,
    ) -> None:
        """Set next RID attribute in RID Set directory."""
        self._session.add(
            Attribute(
                name="rIDNextRID",
                value=str(allocation_params.next_rid),
                directory_id=rid_set.id,
            ),
        )
        self._session.add(
            Attribute(
                name="rIDPreviousAllocationPool",
                value=str(allocation_params.previous_allocation_pool),
                directory_id=rid_set.id,
            ),
        )
        self._session.add(
            Attribute(
                name="rIDAllocationPool",
                value=str(allocation_params.allocation_pool),
                directory_id=rid_set.id,
            ),
        )

    async def get_rid_allocation_pool(self, rid_set: Directory) -> int:
        """Get RID allocation pool from RID Set directory."""
        allocation_pool = await self._session.scalar(
            select(Attribute).where(
                qa(Attribute.name) == "rIDAllocationPool",
                qa(Attribute.directory_id) == rid_set.id,
            ),
        )
        if not (allocation_pool and allocation_pool.value):
            raise RIDManagerRidAllocationPoolNotFoundError(
                "RID allocation pool not found",
            )
        return int(allocation_pool.value)

    async def get_rid_previous_allocation_pool(
        self,
        rid_set: Directory,
    ) -> int:
        """Get previous RID allocation pool from RID Set directory."""
        previous_allocation_pool = await self._session.scalar(
            select(Attribute)
            .where(
                qa(Attribute.name) == "rIDPreviousAllocationPool",
                qa(Attribute.directory_id) == rid_set.id,
            )
            .with_for_update(),
        )
        if not (previous_allocation_pool and previous_allocation_pool.value):
            raise RIDManagerRidPreviousAllocationPoolNotFoundError(
                "previous RID allocation pool not found",
            )
        return int(previous_allocation_pool.value)

    async def get_rid_next_rid(self, rid_set: Directory) -> int:
        """Get next RID from RID Set directory."""
        next_rid = await self._session.scalar(
            select(Attribute)
            .where(
                qa(Attribute.name) == "rIDNextRID",
                qa(Attribute.directory_id) == rid_set.id,
            )
            .with_for_update(),
        )
        if not (next_rid and next_rid.value):
            raise RIDManagerRidNextRIDNotFoundError("next RID not found")
        return int(next_rid.value)

    async def update_next_rid_and_pool(
        self,
        rid_set: Directory,
        next_rid: int,
        previous_allocation_pool: int,
    ) -> None:
        """Update next RID and pool."""
        await self._session.execute(
            update(Attribute)
            .where(
                qa(Attribute.name) == "rIDNextRID",
                qa(Attribute.directory_id) == rid_set.id,
            )
            .values(value=str(next_rid)),
        )
        await self._session.execute(
            update(Attribute)
            .where(
                qa(Attribute.name) == "rIDPreviousAllocationPool",
                qa(Attribute.directory_id) == rid_set.id,
            )
            .values(value=str(previous_allocation_pool)),
        )

    async def reset_attrs_when_pool_exceeded(
        self,
        rid_set: Directory,
        allocation_pool: int,
        previous_allocation_pool: int,
        next_rid: int,
    ) -> None:
        """Reset RID pools when pool exceeded."""
        await self._session.execute(
            update(Attribute)
            .where(
                qa(Attribute.name) == "rIDAllocationPool",
                qa(Attribute.directory_id) == rid_set.id,
            )
            .values(value=str(allocation_pool)),
        )
        await self.update_next_rid_and_pool(
            rid_set,
            next_rid,
            previous_allocation_pool,
        )
