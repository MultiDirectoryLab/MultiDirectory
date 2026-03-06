"""RID Manager Gateway.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import secrets

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from entities import Attribute, Directory
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.rid_manager.exceptions import (
    RIDManagerDomainControllerNotFoundError,
    RIDManagerSystemContainerNotFoundError,
)
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa


class RIDManagerSetupGateway:
    """Gateway for RID Manager setup database operations."""

    def __init__(
        self,
        session: AsyncSession,
        entity_type_dao: EntityTypeDAO,
    ) -> None:
        """Initialize RID Manager setup gateway."""
        self._session = session
        self._entity_type_dao = entity_type_dao

    async def get_domain_controller(self, host_machine_name: str) -> Directory:
        """Get domain controller directory.

        :return: Domain controller directory
        """
        dc = await self._session.scalar(
            select(Directory).where(
                qa(Directory.name) == host_machine_name,
            ),
        )

        if not dc:
            raise RIDManagerDomainControllerNotFoundError(
                "Domain controller not found",
            )

        return dc

    async def get_system_container(self) -> Directory:
        """Get System container directory.

        :return: System container directory
        """
        base_dn_list = await get_base_directories(self._session)

        domain = base_dn_list[0]

        query = select(Directory).where(
            qa(Directory.name) == "System",
            qa(Directory.parent_id) == domain.id,
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
        rid_manager_dir.create_path(system_container, "cn")

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

        await self._entity_type_dao.attach_entity_type_to_directory(
            directory=rid_manager_dir,
            is_system_entity_type=True,
        )

        await self._session.flush()

        return rid_manager_dir

    async def set_rid_available_pool(
        self,
        domain: Directory,
        qword_value: int,
    ) -> None:
        """Set rIDAvailablePool attribute in domain.

        Updates the global RID pool counter.

        :param domain: Domain directory object
        :param qword_value: New QWORD value (64-bit)
        """
        query = (
            update(Attribute)
            .where(
                qa(Attribute.directory_id) == domain.id,
                qa(Attribute.name) == "rIDAvailablePool",
            )
            .values(value=str(qword_value))
        )

        result = await self._session.execute(query)

        if result.rowcount == 0:
            self._session.add(
                Attribute(
                    directory_id=domain.id,
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

    async def create_domain_identifier(self) -> None:
        """Add domain identifier to domain."""
        domain = (await get_base_directories(self._session))[0]

        self._session.add(
            Attribute(
                name="DomainIdentifier",
                value=f"{self._generate_domain_sid_identifier()}",
                directory_id=domain.id,
            ),
        )
        await self._session.flush()
