"""Add rIDManager and rIDSet objectClasses to LDAP schema.

Revision ID: 552b4eafb1aa
Revises: 2dadf40c026a
Create Date: 2026-02-17 09:24:57.906080

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Attribute, Directory, EntityType
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type_use_case import EntityTypeUseCase
from ldap_protocol.rid_manager.gateways import (
    RIDManagerGateway,
    RIDManagerSetupGateway,
)
from ldap_protocol.rid_manager.use_cases import (
    RID_AVAILABLE_MAX,
    RIDManagerSetupUseCase,
)
from ldap_protocol.rid_manager.utils import create_qword
from ldap_protocol.roles.ace_dao import AccessControlEntryDAO
from ldap_protocol.roles.role_dao import RoleDAO
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "552b4eafb1aa"
down_revision: None | str = "ebf19750805e"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:  # noqa: C901
    """Add rIDManager and rIDSet objectClasses to LDAP schema."""

    async def _create_entity_types(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Create rIDManager and rIDSet Entity Types."""
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            entity_type_use_case = await cnt.get(EntityTypeUseCase)

        if not await get_base_directories(session):
            return

        await entity_type_use_case.create(
            EntityTypeDTO(
                name=EntityTypeNames.RID_MANAGER,
                object_class_names=[
                    "top",
                    "rIDManager",
                ],
                is_system=True,
            ),
        )

        await entity_type_use_case.create(
            EntityTypeDTO(
                name=EntityTypeNames.RID_SET,
                object_class_names=[
                    "top",
                    "rIDSet",
                ],
                is_system=True,
            ),
        )

        await session.commit()

    op.run_async(_create_entity_types)

    async def _migrate_object_sids(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Move Directory.objectSid values into Attributes table.

        Additionally, for domain directories move the domain SID prefix part
        into the ``DomainIdentifier`` attribute.
        """
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        directories = await session.scalars(select(Directory))

        for directory in directories:
            if not directory.object_sid:
                continue

            existing_attr = await session.scalar(
                select(Attribute).where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == "objectSid",
                ),
            )

            if not existing_attr:
                session.add(
                    Attribute(
                        name="objectSid",
                        value=directory.object_sid,
                        directory_id=directory.id,
                    ),
                )

            if directory.name == "domain":
                identifier = directory.object_sid.split("-")[
                    -1
                ]  # remove sid prefix

                session.add(
                    Attribute(
                        name="DomainIdentifier",
                        value=identifier,
                        directory_id=directory.id,
                    ),
                )

        await session.commit()

    op.run_async(_migrate_object_sids)

    async def _init_rid_manager(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Initialize RID Manager and RID Set for existing data."""
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
        rid_setup_gateway = await cnt.get(RIDManagerSetupGateway)
        rid_setup_use_case = RIDManagerSetupUseCase(
            rid_manager_setup_gateway=rid_setup_gateway,
            role_dao=await cnt.get(RoleDAO),
            access_control_entry_dao=await cnt.get(AccessControlEntryDAO),
        )
        rid_gateway = RIDManagerGateway(session)

        if not await get_base_directories(session):
            return

        try:
            await rid_gateway.get_rid_manager()
        except ValueError:
            await rid_setup_use_case.setup()
            await session.commit()
            await rid_gateway.get_rid_manager()

        rid_set_dir = await rid_gateway.get_rid_set()

        base_domain = await rid_gateway.get_base_domain()
        domain_identifier = await rid_gateway.get_domain_identifier(
            base_domain,
        )
        sid_prefix = f"S-1-5-21-{domain_identifier}-"

        sid_values = await session.scalars(
            select(Attribute).where(
                qa(Attribute.name) == "objectSid",
                qa(Attribute.value).like(f"{sid_prefix}%"),
            ),
        )

        max_rid = 0
        for sid_value in sid_values:
            if not sid_value or not sid_value.value:
                continue
            try:
                parts = sid_value.value.split("-")
                rid = int(parts[-1])
            except (ValueError, IndexError):
                continue
            if rid > max_rid:
                max_rid = rid

        start_rid = max(max_rid, RIDManagerSetupUseCase.RID_USER_MIN)

        qword = create_qword(start_rid, RID_AVAILABLE_MAX)
        await rid_gateway.update_available_pool(qword)

        result = await session.execute(
            update(Attribute)
            .where(
                qa(Attribute.directory_id) == rid_set_dir.id,
                qa(Attribute.name) == "rIDNextRID",
            )
            .values(value=str(start_rid)),
        )
        if result.rowcount == 0:
            session.add(
                Attribute(
                    directory_id=rid_set_dir.id,
                    name="rIDNextRID",
                    value=str(start_rid),
                ),
            )

        await session.commit()

    op.run_async(_init_rid_manager)

    op.drop_column("Directory", "objectSid")


def downgrade(container: AsyncContainer) -> None:
    """Remove rIDManager and rIDSet objectClasses from LDAP schema."""
    op.add_column(
        "Directory",
        sa.Column("objectSid", sa.String(), nullable=True),
    )

    async def _delete_entity_types(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Delete rIDManager and rIDSet Entity Types."""
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        if not await get_base_directories(session):
            return

        await session.execute(
            delete(EntityType).where(
                qa(EntityType.name).in_(
                    [
                        EntityTypeNames.RID_MANAGER,
                        EntityTypeNames.RID_SET,
                    ],
                ),
            ),
        )

        await session.commit()

    op.run_async(_delete_entity_types)

    async def _delete_rid_manager_dirs(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Delete RID Manager and RID Set directories."""
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        if not await get_base_directories(session):
            return

        await session.execute(
            delete(Directory).where(
                qa(Directory.name).in_(
                    [
                        "RID Manager$",
                        "RID Set",
                    ],
                ),
            ),
        )
        await session.commit()

    op.run_async(_delete_rid_manager_dirs)

    async def _rollback_object_sids(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        """Restore Directory.objectSid values from Attributes.

        Also removes the DomainIdentifier attribute that was introduced in
        upgrade for domain directories.
        """
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        directories = await session.scalars(select(Directory))

        for directory in directories:
            await session.execute(
                delete(Attribute).where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == "DomainIdentifier",
                ),
            )

            attr = await session.scalar(
                select(Attribute).where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == "objectSid",
                ),
            )

            if not attr or not attr.value:
                continue

            directory.object_sid = attr.value

            await session.execute(
                delete(Attribute).where(
                    qa(Attribute.directory_id) == directory.id,
                    qa(Attribute.name) == "objectSid",
                ),
            )

        await session.commit()

    op.run_async(_rollback_object_sids)
