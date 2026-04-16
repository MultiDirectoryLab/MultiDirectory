"""RID Set gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from constants import DOMAIN_CONTROLLERS_OU_NAME
from entities import Attribute, Directory
from ldap_protocol.rid_manager.dtos import RIDSetAllocationParamsDTO
from ldap_protocol.rid_manager.exceptions import (
    RIDManagerRidAllocationPoolNotFoundError,
    RIDManagerRidNextRIDNotFoundError,
    RIDManagerRidPreviousAllocationPoolNotFoundError,
    RIDManagerRidSetNotFoundError,
)
from ldap_protocol.rid_manager.types import HostMachineShortName
from ldap_protocol.utils.async_cache import rid_set_id_cache
from repo.pg.tables import queryable_attr as qa


class RIDSetGateway:
    """RID Set gateway."""

    def __init__(
        self,
        session: AsyncSession,
        host_machine_short_name: HostMachineShortName,
    ) -> None:
        """Initialize RID Set gateway."""
        self._session = session
        self._host_machine_short_name = host_machine_short_name

    @rid_set_id_cache
    async def get_rid_set_id(self) -> int:
        """Get RID Set ID."""
        return await self.get_rid_set_id_value()

    async def get_rid_set_id_value(self) -> int:
        """Get RID Set ID."""
        domain = aliased(Directory)
        domain_controllers_ou = aliased(Directory)
        domain_controller = aliased(Directory)
        rid_set = aliased(Directory)

        rid_set_id = await self._session.scalar(
            select(qa(rid_set.id))
            .select_from(domain)
            .join(
                domain_controllers_ou,
                qa(domain_controllers_ou.parent_id) == qa(domain.id),
            )
            .join(
                domain_controller,
                qa(domain_controller.parent_id)
                == qa(domain_controllers_ou.id),
            )
            .join(
                rid_set,
                qa(rid_set.parent_id) == qa(domain_controller.id),
            )
            .where(
                qa(domain.object_class) == "domain",
                qa(domain.parent_id).is_(None),
                qa(domain_controllers_ou.name) == DOMAIN_CONTROLLERS_OU_NAME,
                qa(domain_controller.name)
                == self._host_machine_short_name,
                qa(rid_set.name) == "RID Set",
            ),
        )
        if rid_set_id is None:
            raise RIDManagerRidSetNotFoundError("RID Set directory not found")
        return int(rid_set_id)

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

    async def create_rid_set_directory(
        self,
        domain_controller: Directory,
    ) -> Directory:
        """Create RID Set directory."""
        rid_set_dir = Directory(
            is_system=True,
            name="RID Set",
        )

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
        rid_set_id: int,
        allocation_params: RIDSetAllocationParamsDTO,
    ) -> None:
        """Set next RID attribute in RID Set directory."""
        self._session.add(
            Attribute(
                name="rIDNextRID",
                value=str(allocation_params.next_rid),
                directory_id=rid_set_id,
            ),
        )
        self._session.add(
            Attribute(
                name="rIDPreviousAllocationPool",
                value=str(allocation_params.previous_allocation_pool),
                directory_id=rid_set_id,
            ),
        )
        self._session.add(
            Attribute(
                name="rIDAllocationPool",
                value=str(allocation_params.allocation_pool),
                directory_id=rid_set_id,
            ),
        )

    async def get_rid_allocation_pool(self, rid_set_id: int) -> int:
        """Get RID allocation pool from RID Set directory."""
        allocation_pool = await self._session.scalar(
            select(Attribute)
            .where(
                qa(Attribute.name) == "rIDAllocationPool",
                qa(Attribute.directory_id) == rid_set_id,
            )
            .with_for_update(),
        )
        if not (allocation_pool and allocation_pool.value):
            raise RIDManagerRidAllocationPoolNotFoundError(
                "RID allocation pool not found",
            )
        return int(allocation_pool.value)

    async def get_rid_previous_allocation_pool(
        self,
        rid_set_id: int,
    ) -> int:
        """Get previous RID allocation pool from RID Set directory."""
        previous_allocation_pool = await self._session.scalar(
            select(Attribute)
            .where(
                qa(Attribute.name) == "rIDPreviousAllocationPool",
                qa(Attribute.directory_id) == rid_set_id,
            )
            .with_for_update(),
        )
        if not (previous_allocation_pool and previous_allocation_pool.value):
            raise RIDManagerRidPreviousAllocationPoolNotFoundError(
                "previous RID allocation pool not found",
            )
        return int(previous_allocation_pool.value)

    async def get_next_rid_value(self, rid_set_id: int) -> int:
        """Get next RID from RID Set directory."""
        next_rid = await self._session.scalar(
            select(Attribute)
            .where(
                qa(Attribute.name) == "rIDNextRID",
                qa(Attribute.directory_id) == rid_set_id,
            )
            .with_for_update(),
        )
        if not (next_rid and next_rid.value):
            raise RIDManagerRidNextRIDNotFoundError("next RID not found")
        return int(next_rid.value)

    async def update_next_rid(
        self,
        rid_set_id: int,
        next_rid: int,
    ) -> None:
        """Update next RID."""
        await self._session.execute(
            update(Attribute)
            .where(
                qa(Attribute.name) == "rIDNextRID",
                qa(Attribute.directory_id) == rid_set_id,
            )
            .values(value=str(next_rid)),
        )

    async def reset_attrs_when_pool_exceeded(
        self,
        rid_set_id: int,
        allocation_pool: int,
        previous_allocation_pool: int,
        next_rid: int,
    ) -> None:
        """Reset RID pools when pool exceeded."""
        await self._session.execute(
            update(Attribute)
            .where(
                qa(Attribute.name) == "rIDAllocationPool",
                qa(Attribute.directory_id) == rid_set_id,
            )
            .values(value=str(allocation_pool)),
        )
        await self._session.execute(
            update(Attribute)
            .where(
                qa(Attribute.name) == "rIDPreviousAllocationPool",
                qa(Attribute.directory_id) == rid_set_id,
            )
            .values(value=str(previous_allocation_pool)),
        )
        await self.update_next_rid(
            rid_set_id,
            next_rid,
        )
