"""RID Manager for issuing RID from pools.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE

"""

from sqlalchemy.ext.asyncio import AsyncSession

from entities import Directory
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import EntityTypeUseCase
from ldap_protocol.rid_manager.rid_manager_use_case import RIDManagerUseCase
from ldap_protocol.rid_manager.rid_set_use_case import RIDSetUseCase
from ldap_protocol.rid_manager.setup_gateway import RIDManagerSetupGateway
from ldap_protocol.rid_manager.utils import to_qword
from ldap_protocol.roles.role_use_case import RoleUseCase


class RIDManagerSetupUseCase:
    """RID Manager setup use case."""

    RID_MIN = 1000
    RID_AVAILABLE_MAX = 1073741822  # 30-bit max (2^30 - 2)

    def __init__(
        self,
        rid_manager_setup_gateway: RIDManagerSetupGateway,
        role_use_case: RoleUseCase,
        rid_set_use_case: RIDSetUseCase,
        rid_manager_use_case: RIDManagerUseCase,
        session: AsyncSession,
        entity_type_use_case: EntityTypeUseCase,
    ) -> None:
        """Initialize RID Manager setup use case.

        :param rid_manager_setup_gateway: Gateway for setup operations
        :param role_use_case: Role use case
        """
        self._gateway = rid_manager_setup_gateway
        self._role_use_case = role_use_case
        self._rid_set_use_case = rid_set_use_case
        self._rid_manager_use_case = rid_manager_use_case
        self._session = session
        self._entity_type_use_case = entity_type_use_case

    async def setup(self) -> None:
        """Create RID Manager."""
        rid_manager_dir = await self._gateway.set_rid_manager()

        await self._entity_type_use_case.attach_entity_type_to_directory(
            directory=rid_manager_dir, is_system_entity_type=True, object_class_names={"top", "rIDManager"}
        )

        await self._session.flush()
        qword = to_qword(self.RID_MIN, self.RID_AVAILABLE_MAX)
        await self._gateway.set_rid_available_pool(rid_manager_dir, qword)
        dc = await self.get_domain_controller()
        await self._rid_set_use_case.add(dc, await self._rid_set_use_case.generate_rid_set_attrs())

        await self._role_use_case.inherit_parent_aces(
            parent_directory=await self._gateway.get_system_container(), directory=rid_manager_dir
        )

    async def create_domain_identifier(self, domain_id: int) -> None:
        """Create domain identifier."""
        await self._gateway.create_domain_identifier(domain_id)

    async def get_domain_controller(self) -> Directory:
        """Get domain controller."""
        return await self._gateway.get_domain_controller()
