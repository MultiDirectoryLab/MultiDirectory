"""RID Set use case.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from sqlalchemy.ext.asyncio import AsyncSession

from entities import Directory
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import (
    EntityTypeUseCase,
)
from ldap_protocol.rid_manager.dtos import RIDSetAllocationParamsDTO
from ldap_protocol.rid_manager.rid_manager_use_case import RIDManagerUseCase
from ldap_protocol.rid_manager.rid_set_gateway import RIDSetGateway
from ldap_protocol.rid_manager.utils import from_qword
from ldap_protocol.roles.role_use_case import RoleUseCase


class RIDSetUseCase:
    """RID Set use case."""

    def __init__(
        self,
        gateway: RIDSetGateway,
        entity_type_use_case: EntityTypeUseCase,
        session: AsyncSession,
        rid_manager_use_case: RIDManagerUseCase,
        role_use_case: RoleUseCase,
    ) -> None:
        """Initialize RID Set use case."""
        self._gateway = gateway
        self._entity_type_use_case = entity_type_use_case
        self._session = session
        self._rid_manager_use_case = rid_manager_use_case
        self._role_use_case = role_use_case

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
        await self._entity_type_use_case.attach_entity_type_to_directory(
            directory=rid_set,
            is_system_entity_type=True,
            object_class_names={"top", "rIDSet"},
        )

        await self._gateway.set_allocation_attrs(
            rid_set.id,
            allocation_params,
        )
        await self.inherit_parent_aces(
            domain_controller=domain_controller,
            rid_set=rid_set,
        )
        await self._session.flush()
        return rid_set

    def is_pool_exceeded(
        self,
        current_next_rid: int,
        previous_allocation_pool: int,
    ) -> bool:
        """Check if RID pool is exceeded."""
        _, upper = from_qword(previous_allocation_pool)

        return current_next_rid + 1 > upper

    async def allocate_next_rid(self, rid_set_id: int) -> int:
        """Allocate next RID."""
        async with self._session.begin_nested():
            current_next_rid = await self._gateway.get_rid_next_rid(rid_set_id)
            previous_allocation_pool = (
                await self._gateway.get_rid_previous_allocation_pool(
                    rid_set_id,
                )
            )

            if self.is_pool_exceeded(
                current_next_rid,
                previous_allocation_pool,
            ):
                new_next_rid = await self.rebind_next_rid_from_new_pool(
                    rid_set_id,
                )
            else:
                new_next_rid = current_next_rid + 1

            await self._gateway.update_next_rid(
                rid_set_id,
                new_next_rid,
            )
        return new_next_rid

    async def rebind_next_rid_from_new_pool(
        self,
        rid_set_id: int,
    ) -> int:
        """Rebind next RID from new pool."""
        new_allocation_pool = await self._rid_manager_use_case.allocate_pool()

        current_allocation_pool = await self._gateway.get_rid_allocation_pool(
            rid_set_id,
        )
        lower, _ = from_qword(current_allocation_pool)
        await self._gateway.reset_attrs_when_pool_exceeded(
            rid_set_id=rid_set_id,
            next_rid=lower,
            allocation_pool=new_allocation_pool,
            previous_allocation_pool=current_allocation_pool,
        )
        return lower

    async def generate_rid_set_attrs(self) -> RIDSetAllocationParamsDTO:
        """Generate RID Set attributes."""
        previous_allocation_pool = (
            await self._rid_manager_use_case.allocate_pool()
        )
        allocation_pool = await self._rid_manager_use_case.allocate_pool()
        lower, _ = from_qword(previous_allocation_pool)

        return RIDSetAllocationParamsDTO(
            next_rid=lower,
            allocation_pool=allocation_pool,
            previous_allocation_pool=previous_allocation_pool,
        )

    async def inherit_parent_aces(
        self,
        domain_controller: Directory,
        rid_set: Directory,
    ) -> None:
        """Inherit parent ACEs to RID Set directory."""
        await self._role_use_case.inherit_parent_aces(
            parent_directory=domain_controller,
            directory=rid_set,
        )
