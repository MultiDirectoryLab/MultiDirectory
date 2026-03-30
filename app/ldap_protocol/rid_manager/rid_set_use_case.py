"""RID Set use case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from entities import Directory
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.rid_manager.dtos import RIDSetAllocationParamsDTO
from ldap_protocol.rid_manager.rid_manager_use_case import RIDManagerUseCase
from ldap_protocol.rid_manager.rid_set_gateway import RIDSetGateway
from ldap_protocol.rid_manager.utils import from_qword, to_qword


class RIDSetUseCase:
    """RID Set use case."""

    def __init__(
        self,
        gateway: RIDSetGateway,
        entity_type_dao: EntityTypeDAO,
        session: AsyncSession,
        rid_manager_use_case: RIDManagerUseCase,
    ) -> None:
        """Initialize RID Set use case."""
        self._gateway = gateway
        self._entity_type_dao = entity_type_dao
        self._session = session
        self._rid_manager_use_case = rid_manager_use_case

    async def get(self, domain_controller: Directory) -> Directory:
        """Get RID Set directory."""
        return await self._gateway.get(domain_controller)

    async def add(
        self,
        domain_controller: Directory,
        allocation_params: RIDSetAllocationParamsDTO,
    ) -> Directory:
        """Create RID Set directory."""
        rid_set = await self._gateway.add(domain_controller)
        await self._entity_type_dao.attach_entity_type_to_directory(
            directory=rid_set,
            is_system_entity_type=True,
        )

        await self._gateway.set_allocation_attrs(
            rid_set,
            allocation_params,
        )
        await self._session.flush()
        return rid_set

    async def is_pool_exceeded(self, rid_set: Directory) -> bool:
        """Check if RID pool is exceeded."""
        next_rid = await self._gateway.get_rid_next_rid(rid_set)
        previous_allocation_pool = (
            await self._gateway.get_rid_previous_allocation_pool(rid_set)
        )
        _, upper = from_qword(previous_allocation_pool)

        return next_rid + 1 >= upper

    async def allocate_next_rid(self, rid_set: Directory) -> int:
        """Allocate next RID."""
        async with self._session.begin_nested():
            if await self.is_pool_exceeded(rid_set):
                previous_allocation_pool = (
                    await self._rid_manager_use_case.allocate_pool()
                )
                await self.reset_attrs_when_pool_exceeded(
                    rid_set,
                    previous_allocation_pool,
                )
            current_rid = await self._gateway.get_rid_next_rid(rid_set)
            previous_allocation_pool = (
                await self._gateway.get_rid_previous_allocation_pool(rid_set)
            )
            _, upper = from_qword(previous_allocation_pool)
            new_rid = current_rid + 1
            new_allocation_pool = to_qword(new_rid, upper)
            await self._gateway.update_next_rid_and_pool(
                rid_set,
                new_rid,
                new_allocation_pool,
            )
        return new_rid

    async def reset_attrs_when_pool_exceeded(
        self,
        rid_set: Directory,
        previous_allocation_pool: int,
    ) -> None:
        """Reset RID pools when pool exceeded."""
        _ = await self._gateway.get_rid_next_rid(rid_set)  # lock next RID

        current_previous_allocation_pool = (
            await self._gateway.get_rid_previous_allocation_pool(
                rid_set,
            )
        )
        lower, _ = from_qword(previous_allocation_pool)
        await self._gateway.reset_attrs_when_pool_exceeded(
            rid_set=rid_set,
            next_rid=lower,
            allocation_pool=current_previous_allocation_pool,
            previous_allocation_pool=previous_allocation_pool,
        )
