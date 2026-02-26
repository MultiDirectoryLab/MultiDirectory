"""RID Manager for issuing RID from pools.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE

"""

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from entities import Directory
from enums import AceType, RoleConstants, RoleScope, SidPrefix
from ldap_protocol.rid_manager.gateways import (
    RIDManagerGateway,
    RIDManagerSetupGateway,
)
from ldap_protocol.rid_manager.utils import create_qword
from ldap_protocol.roles.ace_dao import AccessControlEntryDAO
from ldap_protocol.roles.dataclasses import AccessControlEntryDTO
from ldap_protocol.roles.role_dao import RoleDAO

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
        role_dao: RoleDAO,
        access_control_entry_dao: AccessControlEntryDAO,
    ) -> None:
        """Initialize RID Manager setup use case.

        :param rid_manager_setup_gateway: Gateway for setup operations
        """
        self._gateway = rid_manager_setup_gateway
        self._role_dao = role_dao
        self._access_control_entry_dao = access_control_entry_dao

    async def setup(self) -> None:
        """Create RID Manager."""
        rid_manager_dir = await self._gateway.set_rid_manager()
        await self.grant_domain_admins_read_to_rid_manager(
            rid_manager_dir,
        )

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

    async def grant_domain_admins_read_to_rid_manager(
        self,
        rid_manager_dir: Directory,
    ) -> None:
        """Grant READ access on RID Manager to Domain Admins Role."""
        role = await self._role_dao.get_by_name(
            RoleConstants.DOMAIN_ADMINS_ROLE_NAME,
        )

        await self._access_control_entry_dao.create(
            AccessControlEntryDTO(
                role_id=role.get_id(),
                ace_type=AceType.READ,
                scope=RoleScope.BASE_OBJECT,
                base_dn=rid_manager_dir.path_dn,
                attribute_type_id=None,
                entity_type_id=None,
                is_allow=True,
            ),
        )

    async def create_domain_identifier(self) -> None:
        """Create domain identifier."""
        await self._gateway.create_domain_identifier()
