"""RID Manager Gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import secrets

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from constants import DOMAIN_CONTROLLERS_OU_NAME, SYSTEM_CONTAINER_NAME
from entities import Attribute, Directory
from ldap_protocol.rid_manager.exceptions import (
    RIDManagerDomainControllerNotFoundError,
    RIDManagerSystemContainerNotFoundError,
)
from ldap_protocol.rid_manager.types import HostMachineShortName
from repo.pg.tables import queryable_attr as qa


class RIDManagerSetupGateway:
    """Gateway for RID Manager setup database operations."""

    def __init__(
        self,
        session: AsyncSession,
        host_machine_short_name: HostMachineShortName,
    ) -> None:
        """Initialize RID Manager setup gateway."""
        self._session = session
        self._host_machine_short_name = host_machine_short_name

    async def get_system_container(self) -> Directory:
        """Get System container directory.

        :return: System container directory
        """
        query = select(Directory).where(
            qa(Directory.name) == SYSTEM_CONTAINER_NAME,
            qa(Directory.is_system).is_(True),
        )

        system_container = await self._session.scalar(query)

        if not system_container:
            raise RIDManagerSystemContainerNotFoundError(
                "System container not found",
            )

        return system_container

    async def set_rid_manager(self) -> Directory:
        """Create RID Manager directory."""
        system_container = await self.get_system_container()

        rid_manager_dir = Directory(
            is_system=True,
            name="RID Manager$",
        )

        self._session.add(rid_manager_dir)
        await self._session.flush()

        rid_manager_dir.parent_id = system_container.id
        await self._session.refresh(rid_manager_dir, ["id"])

        self._session.add(
            Attribute(
                name="cn",
                value="RID Manager$",
                directory_id=rid_manager_dir.id,
            ),
        )

        self._session.add(
            Attribute(
                name="objectClass",
                value="top",
                directory_id=rid_manager_dir.id,
            ),
        )

        self._session.add(
            Attribute(
                name="objectClass",
                value="rIDManager",
                directory_id=rid_manager_dir.id,
            ),
        )

        await self._session.flush()

        await self._session.refresh(
            instance=rid_manager_dir,
            attribute_names=["attributes"],
            with_for_update=None,
        )

        return rid_manager_dir

    async def set_rid_available_pool(
        self,
        rid_manager_dir: Directory,
        qword_value: int,
    ) -> None:
        """Set rIDAvailablePool attribute in domain.

        Updates the global RID pool counter.

        :param rid_manager_dir: RID Manager directory object
        :param qword_value: New QWORD value (64-bit)
        """
        self._session.add(
            Attribute(
                directory_id=rid_manager_dir.id,
                name="rIDAvailablePool",
                value=str(qword_value),
            ),
        )

        await self._session.flush()

    def _generate_domain_sid_identifier(self) -> str:
        """Generate Domain Identifier for Active Directory domain."""
        return (
            f"{secrets.randbits(32)}"
            f"-{secrets.randbits(32)}-{secrets.randbits(32)}"
        )

    async def create_domain_identifier(self, domain_id: int) -> None:
        """Add domain identifier to domain."""
        domain_identifer = await self._session.scalar(
            select(
                exists(Attribute),
            ).where(
                qa(Attribute.name) == "DomainIdentifier",
            ),
        )

        if domain_identifer:
            return

        self._session.add(
            Attribute(
                name="DomainIdentifier",
                value=f"{self._generate_domain_sid_identifier()}",
                directory_id=domain_id,
            ),
        )
        await self._session.flush()

    async def get_domain_controller(self) -> Directory:
        """Get domain controller."""
        domain_controller = await self._session.scalar(
            select(Directory).where(
                qa(Directory.name) == self._host_machine_short_name,
                qa(Directory.parent).has(
                    qa(Directory.name) == DOMAIN_CONTROLLERS_OU_NAME,
                ),
            ),
        )

        if not domain_controller:
            raise RIDManagerDomainControllerNotFoundError(
                "Domain controller not found",
            )

        return domain_controller
