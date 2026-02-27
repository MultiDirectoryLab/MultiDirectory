"""RID Manager for issuing RID from pools.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE

"""

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from entities import Directory
from enums import SidPrefix
from ldap_protocol.rid_manager.gateways import (
    RIDManagerGateway,
    RIDManagerSetupGateway,
)
from ldap_protocol.rid_manager.utils import create_qword
from ldap_protocol.roles.ace_dao import AccessControlEntryDAO
from ldap_protocol.roles.role_use_case import RoleUseCase

RID_AVAILABLE_MAX = 1073741822  # 30-bit max (2^30 - 2)


class RIDManagerUseCase:
    """RID Manager Use Case for issuing RID from pools."""

    def __init__(
        self,
        gateway: RIDManagerGateway,
        session: AsyncSession,
    ) -> None:
        """Initialize RID Manager Use Case.

        :param gateway: RID Manager Gateway for database operations
        """
        self._gateway = gateway
        self._lock = asyncio.Lock()
        self._session = session

    async def get_object_sid(
        self,
        directory: Directory,
    ) -> str:
        """Get object SID for directory."""
        return await self._gateway.get_object_sid(directory)

    async def get_rid_set(self) -> Directory | None:
        """Get RID Set directory."""
        return await self._gateway.get_rid_set()

    async def set_object_sid(
        self,
        directory: Directory,
        rid: int | None = None,
        sid_prefix: SidPrefix = SidPrefix.DOMAIN_IDENTIFIER,
    ) -> None:
        """Create object SID."""
        async with self._lock, await self._session.begin_nested():
            if rid is None:
                rid_set = await self._gateway.get_rid_set()
                if not rid_set:
                    raise ValueError("RID Set directory not found")

                next_rid = await self._gateway.get_next_rid(rid_set)
                rid = next_rid + 1
                await self._gateway.update_next_rid(rid_set, rid)
                await self._gateway.update_available_pool(
                    create_qword(rid, RID_AVAILABLE_MAX),
                )

            if sid_prefix == SidPrefix.BUILT_IN_DOMAIN:
                sid = f"{sid_prefix}-{rid}"
            elif sid_prefix == SidPrefix.DOMAIN_IDENTIFIER:
                base_domain = await self._gateway.get_base_domain()
                domain_identifier = await self._gateway.get_domain_identifier(
                    base_domain,
                )
                sid = f"{sid_prefix}-{domain_identifier}-{rid}"

            await self._gateway.add_object_sid(directory, sid)

            await self._session.flush()

    async def parse_object_sid(self, object_sid: str) -> tuple[str, str, int]:
        """Parse object SID.

        :param object_sid: Object SID
        :return: Tuple containing domain identifier, rid, and reserved flag
        """
        parts = object_sid.split("-")
        return parts[1], parts[2], int(parts[3])


class RIDManagerSetupUseCase:
    """RID Manager setup use case."""

    RID_SYSTEM_MIN = 1
    RID_SYSTEM_MAX = 499
    RID_BUILTIN_MIN = 500
    RID_BUILTIN_MAX = 1000
    RID_USER_MIN = 1100

    def __init__(
        self,
        rid_manager_setup_gateway: RIDManagerSetupGateway,
        role_use_case: RoleUseCase,
        access_control_entry_dao: AccessControlEntryDAO,
    ) -> None:
        """Initialize RID Manager setup use case.

        :param rid_manager_setup_gateway: Gateway for setup operations
        :param role_use_case: Role use case
        """
        self._gateway = rid_manager_setup_gateway
        self._role_use_case = role_use_case
        self._access_control_entry_dao = access_control_entry_dao

    async def setup(self) -> None:
        """Create RID Manager."""
        rid_manager_dir = await self._gateway.set_rid_manager()

        qword = create_qword(self.RID_USER_MIN, RID_AVAILABLE_MAX)

        await self._gateway.set_rid_available_pool(
            rid_manager_dir,
            qword,
        )
        domain_controller = await self._gateway.get_domain_controller()

        rid_set_dir = await self._gateway.create_rid_set(
            domain_controller,
        )
        await self._gateway.set_next_rid(
            rid_set_dir,
            self.RID_USER_MIN,
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

        domain_controller = await self._gateway.get_domain_controller()
        await self._role_use_case.inherit_parent_aces(
            parent_directory=domain_controller,
            directory=await self._gateway.get_rid_set(domain_controller),
        )

    async def create_domain_identifier(self) -> None:
        """Create domain identifier."""
        await self._gateway.create_domain_identifier()
