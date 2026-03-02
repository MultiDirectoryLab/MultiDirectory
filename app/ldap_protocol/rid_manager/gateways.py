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
    RIDManagerAvailablePoolNotFoundError,
    RIDManagerDomainControllerNotFoundError,
    RIDManagerDomainIdentifierNotFoundError,
    RIDManagerDomainNotFoundError,
    RIDManagerNextRIDNotFoundError,
    RIDManagerNotFoundError,
    RIDManagerObjectSidNotFoundError,
    RIDManagerRidSetNotFoundError,
    RIDManagerSystemContainerNotFoundError,
)
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa


class RIDManagerGateway:
    """Gateway for RID Manager database operations.

    Handles all database operations for RID Manager:
    - Reading/writing rIDAvailablePool (global pool in CN=RID Manager$)
    - Reading/writing rIDNextRID (local counter, non-replicated)
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize RID Manager Gateway.

        :param session: SQLAlchemy async session
        """
        self._session = session

    async def get_rid_available_pool(self, domain: Directory) -> int:
        """Get rIDAvailablePool attribute from domain.

        This is a QWORD (64-bit) value where:
        - Lower 32 bits: next available RID
        - Upper 32 bits: maximum RID in pool

        :param domain: Domain directory object
        :return: QWORD value of rIDAvailablePool
        """
        query = await self._session.scalar(
            select(Attribute).where(
                qa(Attribute.directory_id) == domain.id,
                qa(Attribute.name) == "rIDAvailablePool",
            ),
        )

        if not query or not query.value:
            raise RIDManagerAvailablePoolNotFoundError(
                "rIDAvailablePool attribute not found",
            )

        return int(query.value)

    async def get_next_rid(self, domain: Directory) -> int:
        """Get next RID attribute from domain.

        This is the last issued RID (not the next one, despite the name).
        This attribute is NOT replicated.

        :param domain: Domain directory object
        :return: Last issued RID or None if not set
        """
        query = await self._session.scalar(
            select(Attribute)
            .where(
                qa(Attribute.directory_id) == domain.id,
                qa(Attribute.name) == "rIDNextRID",
            )
            .with_for_update(),
        )

        if not query or not query.value:
            raise RIDManagerNextRIDNotFoundError(
                "next RID attribute not found",
            )
        return int(query.value)

    async def get_domain_identifier(self, domain: Directory) -> str:
        """Get domain identifier.

        :return: Domain identifier
        """
        query = await self._session.scalar(
            select(Attribute).where(
                qa(Attribute.name) == "DomainIdentifier",
                qa(Attribute.directory_id) == domain.id,
            ),
        )

        if not query or not query.value:
            raise RIDManagerDomainIdentifierNotFoundError(
                "domain identifier not found",
            )

        return query.value

    async def get_rid_set(self) -> Directory | None:
        """Get RID Set directory.

        :return: RID Set directory
        """
        return await self._session.scalar(
            select(Directory).where(qa(Directory.name) == "RID Set"),
        )

    async def update_next_rid(self, rid_set: Directory, next_rid: int) -> None:
        """Update next RID attribute in RID Set directory.

        :param rid_set: RID Set directory
        :param next_rid: Next RID
        """
        await self._session.execute(
            update(Attribute)
            .where(
                qa(Attribute.directory_id) == rid_set.id,
                qa(Attribute.name) == "rIDNextRID",
            )
            .values(value=str(next_rid)),
        )

    async def get_rid_manager(self) -> Directory:
        """Get RID Manager directory.

        :return: RID Manager directory
        """
        rid_manager = await self._session.scalar(
            select(Directory).where(qa(Directory.name) == "RID Manager$"),
        )
        if not rid_manager:
            raise RIDManagerNotFoundError("RID Manager directory not found")

        return rid_manager

    async def update_available_pool(
        self,
        qword_value: int,
    ) -> None:
        """Update available pool attribute in RID Manager directory.

        :param rid_manager: RID Manager directory
        :param qword_value: QWORD value
        """
        rid_manager = await self.get_rid_manager()
        await self._session.execute(
            update(Attribute)
            .where(
                qa(Attribute.directory_id) == rid_manager.id,
                qa(Attribute.name) == "rIDAvailablePool",
            )
            .values(value=str(qword_value)),
        )

    async def add_object_sid(
        self,
        directory: Directory,
        object_sid: str,
    ) -> None:
        """Add object SID to directory.

        :param directory: Directory
        :param object_sid: Object SID
        """
        self._session.add(
            Attribute(
                name="objectSid",
                value=object_sid,
                directory_id=directory.id,
            ),
        )

    async def get_object_sid(
        self,
        rid_set: Directory,
    ) -> str:
        """Get object SID from directory.

        :param rid_set: RID Set directory
        :return: Object SID
        """
        query = await self._session.scalar(
            select(Attribute).where(
                qa(Attribute.directory_id) == rid_set.id,
                qa(Attribute.name) == "objectSid",
            ),
        )
        if not query or not query.value:
            raise RIDManagerObjectSidNotFoundError("object SID not found")
        return query.value

    async def get_base_domain(self) -> Directory:
        """Get base domain directory.

        :return: Base domain directory
        """
        base_domain = await self._session.scalar(
            select(Directory).where(qa(Directory.object_class) == "domain"),
        )
        if not base_domain:
            raise RIDManagerDomainNotFoundError("base domain not found")
        return base_domain


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

    async def create_rid_set(
        self,
        domain_controller: Directory,
    ) -> Directory:
        """Create CN=RID Set directory under Domain Controller.

        :param domain_controller: Domain Controller directory object
        :return: Created RID Set directory
        """
        rid_set_dir = Directory(
            is_system=True,
            name="RID Set",
        )
        rid_set_dir.create_path(domain_controller, "cn")

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

        await self._entity_type_dao.attach_entity_type_to_directory(
            directory=rid_set_dir,
            is_system_entity_type=True,
        )

        await self._session.flush()

        return rid_set_dir

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

    async def set_next_rid(
        self,
        domain: Directory,
        rid: int,
    ) -> None:
        """Set next RID attribute in domain.

        Updates the last issued RID counter.

        :param domain: Domain directory object
        :param rid: Last issued RID value
        """
        self._session.add(
            Attribute(
                directory_id=domain.id,
                name="rIDNextRID",
                value=str(rid),
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
        domain = await self._session.scalar(
            select(Directory).where(
                qa(Directory.object_class) == "domain",
            ),
        )
        if not domain:
            raise RIDManagerDomainNotFoundError("Domain not found")

        self._session.add(
            Attribute(
                name="DomainIdentifier",
                value=f"{self._generate_domain_sid_identifier()}",
                directory_id=domain.id,
            ),
        )
        await self._session.flush()

    async def get_domain_identifier(self) -> str:
        """Get domain identifier."""
        domain = await self._session.scalar(
            select(Attribute).where(
                qa(Attribute.name) == "DomainIdentifier",
            ),
        )
        if not domain or not domain.value:
            raise RIDManagerDomainIdentifierNotFoundError("Domain not found")
        return domain.value

    async def get_rid_set(self, domain_controller: Directory) -> Directory:
        """Get RID Set directory.

        :param domain_controller: Domain controller directory
        :return: RID Set directory
        """
        rid_set = await self._session.scalar(
            select(Directory).where(
                qa(Directory.name) == "RID Set",
                qa(Directory.parent_id) == domain_controller.id,
            ),
        )
        if not rid_set:
            raise RIDManagerRidSetNotFoundError("RID Set directory not found")
        return rid_set
