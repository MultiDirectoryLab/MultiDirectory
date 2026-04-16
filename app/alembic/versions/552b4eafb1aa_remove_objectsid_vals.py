"""Add rIDManager and rIDSet objectClasses to LDAP schema.

Revision ID: 552b4eafb1aa
Revises: 1b71cafba681
Create Date: 2026-02-17 09:24:57.906080

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from constants import (
    COMPUTERS_CONTAINER_NAME,
    CONFIGURATION_DIR_NAME,
    DOMAIN_ADMIN_GROUP_NAME,
    DOMAIN_COMPUTERS_GROUP_NAME,
    DOMAIN_CONTROLLERS_OU_NAME,
    DOMAIN_USERS_GROUP_NAME,
    GROUPS_CONTAINER_NAME,
    READ_ONLY_GROUP_NAME,
    SYSTEM_CONTAINER_NAME,
    USERS_CONTAINER_NAME,
)
from entities import Attribute, Directory, EntityType
from enums import EntityTypeNames, SecurityPrincipalRid
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import (
    EntityTypeUseCase,
)
from ldap_protocol.rid_manager import (
    RIDManagerGateway,
    RIDManagerSetupGateway,
    RIDManagerSetupUseCase,
    RIDManagerUseCase,
    RIDSetUseCase,
)
from ldap_protocol.rid_manager.dtos import RIDSetAllocationParamsDTO
from ldap_protocol.rid_manager.exceptions import (
    RIDManagerNotFoundError,
    RIDManagerRidSetNotFoundError,
)
from ldap_protocol.rid_manager.rid_set_gateway import RIDSetGateway
from ldap_protocol.rid_manager.utils import from_qword, to_qword
from ldap_protocol.roles.role_use_case import RoleUseCase
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "552b4eafb1aa"
down_revision: None | str = "1b71cafba681"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


async def _directory_ids_skipped_for_object_sid_migration(
    session: AsyncSession,
    domain: Directory,
) -> set[int]:
    """Directory ids for which objectSid is not copied into Attributes.

    Top-level peer containers (System, OU DC, Users, Computers, Groups) and
    the full subtree under ``Configuration``.
    """
    peer_container_names = (
        SYSTEM_CONTAINER_NAME,
        DOMAIN_CONTROLLERS_OU_NAME,
        USERS_CONTAINER_NAME,
        COMPUTERS_CONTAINER_NAME,
        GROUPS_CONTAINER_NAME,
    )
    peer_rows = await session.scalars(
        select(qa(Directory.id)).where(
            qa(Directory.parent_id) == domain.id,
            qa(Directory.name).in_(peer_container_names),
        ),
    )
    skip_ids: set[int] = set(peer_rows.all())
    configuration_id = await session.scalar(
        select(qa(Directory.id)).where(
            qa(Directory.parent_id) == domain.id,
            qa(Directory.name) == CONFIGURATION_DIR_NAME,
        ),
    )
    if configuration_id is None:
        return skip_ids

    subtree = (
        select(qa(Directory.id))
        .where(qa(Directory.id) == configuration_id)
        .cte(name="subtree", recursive=True)
    )
    subtree = subtree.union_all(
        select(qa(Directory.id)).where(
            qa(Directory.parent_id) == subtree.c.id,
        ),
    )
    cfg_rows = await session.execute(select(subtree.c.id))
    skip_ids |= {row[0] for row in cfg_rows.all()}
    return skip_ids


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

        Add ``DomainIdentifier`` on the domain (from ``Directory.objectSid``
        column when present). Do not store domain ``objectSid`` in Attributes.
        Normalize built-in group / administrator SIDs once.
        """
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return
        domain = base_dn_list[0]

        skip_object_sid_ids = (
            await _directory_ids_skipped_for_object_sid_migration(
                session,
                domain,
            )
        )

        directory_table = sa.table(
            "Directory",
            sa.column("id", sa.Integer),
            sa.column("parentId", sa.Integer),
            sa.column("objectSid", sa.String),
        )

        domain_sid_from_column = await session.scalar(
            select(directory_table.c.objectSid).where(
                directory_table.c.id == domain.id,
            ),
        )

        domain_identifier: str | None = None
        if domain_sid_from_column:
            parts = domain_sid_from_column.split("-")
            # "S-1-5-21-AAA-BBB-CCC" -> "AAA-BBB-CCC"
            if len(parts) >= 7 and domain_sid_from_column.startswith(
                "S-1-5-21-",
            ):
                domain_identifier = "-".join(parts[4:7])

        session.add(
            Attribute(
                name="DomainIdentifier",
                value=domain_identifier,
                directory_id=domain.id,
            ),
        )
        result = (
            await session.execute(
                select(
                    directory_table.c.id,
                    directory_table.c.parentId,
                    directory_table.c.objectSid,
                ),
            )
        ).all()
        for directory_id, parent_id, object_sid in result:
            if not object_sid:
                continue
            if parent_id is None:
                continue
            if directory_id in skip_object_sid_ids:
                continue

            session.add(
                Attribute(
                    name="objectSid",
                    value=object_sid,
                    directory_id=directory_id,
                ),
            )

        sid_prefix = "S-1-5-21"
        for dir_name, rid in (
            (DOMAIN_ADMIN_GROUP_NAME, SecurityPrincipalRid.DOMAIN_ADMINS),
            (DOMAIN_USERS_GROUP_NAME, SecurityPrincipalRid.DOMAIN_USERS),
            (
                DOMAIN_COMPUTERS_GROUP_NAME,
                SecurityPrincipalRid.DOMAIN_COMPUTERS,
            ),
            (READ_ONLY_GROUP_NAME, SecurityPrincipalRid.DOMAIN_READ_ONLY),
        ):
            await session.execute(
                update(Attribute)
                .where(
                    qa(Attribute.name) == "objectSid",
                    qa(Attribute.directory_id).in_(
                        select(qa(Directory.id)).where(
                            qa(Directory.name) == dir_name,
                        ),
                    ),
                )
                .values(
                    value=f"{sid_prefix}-{domain_identifier}-{int(rid)}",
                ),
            )

        await session.execute(
            update(Attribute)
            .where(
                qa(Attribute.name) == "objectSid",
                qa(Attribute.value).like(
                    f"S-1-5-21-%-{int(SecurityPrincipalRid.ADMINISTRATOR)}",
                ),
            )
            .values(
                value=(
                    f"{sid_prefix}"
                    f"-{domain_identifier}-{int(SecurityPrincipalRid.ADMINISTRATOR)}"
                ),
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
            rid_gateway = await cnt.get(RIDManagerGateway)
            rid_manager_use_case = await cnt.get(RIDManagerUseCase)
            rid_set_gateway = await cnt.get(RIDSetGateway)
            rid_set_use_case = await cnt.get(RIDSetUseCase)
            role_use_case = await cnt.get(RoleUseCase)

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return
        domain = base_dn_list[0]

        try:
            rid_manager_dir = await rid_gateway.get_rid_manager()
        except RIDManagerNotFoundError:
            rid_manager_dir = await rid_setup_gateway.set_rid_manager()

        domain_identifier = await session.scalar(
            select(Attribute).where(
                qa(Attribute.directory_id) == domain.id,
                qa(Attribute.name) == "DomainIdentifier",
            ),
        )
        if not (domain_identifier and domain_identifier.value):
            return

        sid_prefix = f"S-1-5-21-{domain_identifier.value}-"

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

        start_rid = max(max_rid, RIDManagerSetupUseCase.RID_MIN)

        qword = to_qword(start_rid, RIDManagerSetupUseCase.RID_AVAILABLE_MAX)

        await rid_setup_gateway.set_rid_available_pool(rid_manager_dir, qword)

        system_container = await rid_setup_gateway.get_system_container()
        await role_use_case.inherit_parent_aces(
            parent_directory=system_container,
            directory=rid_manager_dir,
        )

        domain_controller = await rid_setup_gateway.get_domain_controller()
        try:
            await rid_set_gateway.get(domain_controller)
        except RIDManagerRidSetNotFoundError:
            previous_allocation_pool = (
                await rid_manager_use_case.allocate_pool()
            )
            allocation_pool = await rid_manager_use_case.allocate_pool()
            lower, _ = from_qword(previous_allocation_pool)

            await rid_set_use_case.add(
                domain_controller,
                RIDSetAllocationParamsDTO(
                    next_rid=lower,
                    allocation_pool=allocation_pool,
                    previous_allocation_pool=previous_allocation_pool,
                ),
            )

            await session.commit()
            return

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

        directory_table = sa.table(
            "Directory",
            sa.column("id", sa.Integer),
            sa.column("objectSid", sa.String),
        )

        result = await session.execute(select(directory_table.c.id))

        for (directory_id,) in result:
            await session.execute(
                delete(Attribute).where(
                    qa(Attribute.directory_id) == directory_id,
                    qa(Attribute.name) == "DomainIdentifier",
                ),
            )

            attr = await session.scalar(
                select(Attribute).where(
                    qa(Attribute.directory_id) == directory_id,
                    qa(Attribute.name) == "objectSid",
                ),
            )

            if not attr or not attr.value:
                continue

            await session.execute(
                update(directory_table)
                .where(directory_table.c.id == directory_id)
                .values(objectSid=attr.value),
            )

            await session.execute(
                delete(Attribute).where(
                    qa(Attribute.directory_id) == directory_id,
                    qa(Attribute.name) == "objectSid",
                ),
            )

        await session.commit()

    op.run_async(_rollback_object_sids)
