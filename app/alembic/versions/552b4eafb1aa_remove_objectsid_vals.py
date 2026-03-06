"""Add rIDManager and rIDSet objectClasses to LDAP schema.

Revision ID: 552b4eafb1aa
Revises: 2dadf40c026a
Create Date: 2026-02-17 09:24:57.906080

"""

import secrets

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Attribute, Directory, EntityType
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.dto import EntityTypeDTO
from ldap_protocol.ldap_schema.entity_type_use_case import EntityTypeUseCase
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
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "552b4eafb1aa"
down_revision: None | str = "2dadf40c026a"
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

        Additionally, for domain directories create the ``DomainIdentifier``
        attribute if it does not exist.
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

        base_dn_list = await get_base_directories(session)
        if base_dn_list:
            domain = base_dn_list[0]

            existing_identifier = await session.scalar(
                select(Attribute).where(
                    qa(Attribute.directory_id) == domain.id,
                    qa(Attribute.name) == "DomainIdentifier",
                ),
            )

            if not (existing_identifier and existing_identifier.value):
                domain_object_sid = await session.scalar(
                    select(Attribute).where(
                        qa(Attribute.directory_id) == domain.id,
                        qa(Attribute.name) == "objectSid",
                    ),
                )

                identifier: str | None = None
                if domain_object_sid and domain_object_sid.value:
                    parts = domain_object_sid.value.split("-")
                    # "S-1-5-21-AAA-BBB-CCC" -> "AAA-BBB-CCC"
                    if len(parts) >= 7 and domain_object_sid.value.startswith(
                        "S-1-5-21-",
                    ):
                        identifier = "-".join(parts[4:7])

                if identifier is None:
                    identifier = (
                        f"{secrets.randbits(32)}-"
                        f"{secrets.randbits(32)}-"
                        f"{secrets.randbits(32)}"
                    )

                session.add(
                    Attribute(
                        name="DomainIdentifier",
                        value=identifier,
                        directory_id=domain.id,
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

        if not await get_base_directories(session):
            return

        try:
            rid_manager_dir = await rid_gateway.get_rid_manager()
        except RIDManagerNotFoundError:
            rid_manager_dir = await rid_setup_gateway.set_rid_manager()

        base_dn_list = await get_base_directories(session)
        if not base_dn_list:
            return
        domain = base_dn_list[0]

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

        start_rid = max(max_rid, RIDManagerSetupUseCase.RID_USER_MIN)

        qword = to_qword(start_rid, RIDManagerSetupUseCase.RID_AVAILABLE_MAX)
        await rid_setup_gateway.set_rid_available_pool(rid_manager_dir, qword)

        domain_controller = await rid_gateway.get_domain_controller()
        rid_set_dir: Directory | None = None
        try:
            rid_set_dir = await rid_set_gateway.get(domain_controller)
        except RIDManagerRidSetNotFoundError:
            rid_set_dir = None

        if rid_set_dir is None:
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

        existing_next_rid = await session.scalar(
            select(Attribute).where(
                qa(Attribute.directory_id) == rid_set_dir.id,
                qa(Attribute.name) == "rIDNextRID",
            ),
        )
        existing_prev_pool = await session.scalar(
            select(Attribute).where(
                qa(Attribute.directory_id) == rid_set_dir.id,
                qa(Attribute.name) == "rIDPreviousAllocationPool",
            ),
        )
        existing_pool = await session.scalar(
            select(Attribute).where(
                qa(Attribute.directory_id) == rid_set_dir.id,
                qa(Attribute.name) == "rIDAllocationPool",
            ),
        )

        if (
            existing_next_rid
            and existing_next_rid.value
            and existing_prev_pool
            and existing_prev_pool.value
            and existing_pool
            and existing_pool.value
        ):
            await session.commit()
            return

        previous_allocation_pool = await rid_manager_use_case.allocate_pool()
        allocation_pool = await rid_manager_use_case.allocate_pool()
        lower, _ = from_qword(previous_allocation_pool)

        for name, value in (
            ("rIDNextRID", str(lower)),
            ("rIDPreviousAllocationPool", str(previous_allocation_pool)),
            ("rIDAllocationPool", str(allocation_pool)),
        ):
            result = await session.execute(
                update(Attribute)
                .where(
                    qa(Attribute.directory_id) == rid_set_dir.id,
                    qa(Attribute.name) == name,
                )
                .values(value=value),
            )
            if result.rowcount == 0:
                session.add(
                    Attribute(
                        directory_id=rid_set_dir.id,
                        name=name,
                        value=value,
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
