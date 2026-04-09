"""RID Manager for issuing RID from pools.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE

"""

from config import Settings
from entities import Directory
from ldap_protocol.rid_manager.rid_manager_use_case import RIDManagerUseCase
from ldap_protocol.rid_manager.rid_set_use_case import RIDSetUseCase
from ldap_protocol.rid_manager.setup_gateway import RIDManagerSetupGateway
from ldap_protocol.rid_manager.utils import to_qword
from ldap_protocol.roles.ace_dao import AccessControlEntryDAO
from ldap_protocol.roles.role_use_case import RoleUseCase


class RIDManagerSetupUseCase:
    """RID Manager setup use case."""

    RID_MIN = 1100
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
        rid_manager_dir = await self._gateway.set_rid_manager()
        qword = to_qword(self.RID_MIN, self.RID_AVAILABLE_MAX)
        await self._gateway.set_rid_available_pool(
            rid_manager_dir,
            qword,
        )
        dc = await self._rid_manager_use_case.get_domain_controller()
        await self._rid_set_use_case.add(
            dc,
            await self._rid_set_use_case.generate_rid_set_attrs(),
        )

        await self.inherit_aces(
            rid_manager_dir,
        )

    async def inherit_aces(
        self,
        rid_manager_dir: Directory,
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

    async def create_domain_identifier(self, domain_id: int) -> None:
        """Create domain identifier."""
        await self._gateway.create_domain_identifier(domain_id)
