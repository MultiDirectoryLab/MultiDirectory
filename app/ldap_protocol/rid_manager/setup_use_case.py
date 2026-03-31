"""RID Manager for issuing RID from pools.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE

"""

from config import Settings
from entities import Directory
from ldap_protocol.rid_manager.dtos import RIDSetAllocationParamsDTO
from ldap_protocol.rid_manager.rid_manager_use_case import RIDManagerUseCase
from ldap_protocol.rid_manager.rid_set_use_case import RIDSetUseCase
from ldap_protocol.rid_manager.setup_gateway import RIDManagerSetupGateway
from ldap_protocol.rid_manager.utils import from_qword, to_qword
from ldap_protocol.roles.ace_dao import AccessControlEntryDAO
from ldap_protocol.roles.role_use_case import RoleUseCase


class RIDManagerSetupUseCase:
    """RID Manager setup use case."""

    RID_BUILTIN_MIN = 500
    RID_BUILTIN_MAX = 1000
    RID_USER_MIN = 1100
    RID_AVAILABLE_MAX = 1073741822  # 30-bit max (2^30 - 2)

    def __init__(
        self,
        rid_manager_setup_gateway: RIDManagerSetupGateway,
        role_use_case: RoleUseCase,
        access_control_entry_dao: AccessControlEntryDAO,
        rid_set_use_case: RIDSetUseCase,
        rid_manager_use_case: RIDManagerUseCase,
        settings: Settings,
    ) -> None:
        """Initialize RID Manager setup use case.

        :param rid_manager_setup_gateway: Gateway for setup operations
        :param role_use_case: Role use case
        """
        self._gateway = rid_manager_setup_gateway
        self._role_use_case = role_use_case
        self._access_control_entry_dao = access_control_entry_dao
        self._settings = settings
        self._rid_set_use_case = rid_set_use_case
        self._rid_manager_use_case = rid_manager_use_case

    async def setup(self) -> None:
        """Create RID Manager."""
        await self.create_domain_identifier()
        rid_manager_dir = await self._gateway.set_rid_manager()
        qword = to_qword(self.RID_USER_MIN, self.RID_AVAILABLE_MAX)
        await self._gateway.set_rid_available_pool(
            rid_manager_dir,
            qword,
        )
        dc = await self._rid_manager_use_case.get_domain_controller()
        rid_set = await self._create_rid_set(dc)

        await self.inherit_aces(
            rid_manager_dir,
            dc,
            rid_set,
        )

    async def _create_rid_set(self, domain_controller: Directory) -> Directory:
        previous_allocation_pool = (
            await self._rid_manager_use_case.allocate_pool()
        )
        allocation_pool = await self._rid_manager_use_case.allocate_pool()
        lower, _ = from_qword(previous_allocation_pool)

        return await self._rid_set_use_case.add(
            domain_controller,
            RIDSetAllocationParamsDTO(
                next_rid=lower,
                allocation_pool=allocation_pool,
                previous_allocation_pool=previous_allocation_pool,
            ),
        )

    async def inherit_aces(
        self,
        rid_manager_dir: Directory,
        domain_controller: Directory,
        rid_set: Directory,
    ) -> None:
        """Inherit ACEs from domain root to RID Manager directory.

        Instead of creating a special ACE or role for RID Manager,
        we reuse the existing ACL model: all ACEs that apply to the
        domain root (including Domain Admins) are inherited by the
        `CN=RID Manager$` directory, similar to how it is done in
        migration `ebf19750805e_add_domain_controllers_ou`.
        """
        await self._role_use_case.inherit_parent_aces(
            parent_directory=await self._gateway.get_system_container(),
            directory=rid_manager_dir,
        )

        await self._role_use_case.inherit_parent_aces(
            parent_directory=domain_controller,
            directory=rid_set,
        )

    async def create_domain_identifier(self) -> None:
        """Create domain identifier."""
        await self._gateway.create_domain_identifier()
