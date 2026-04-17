"""Add objectSid to objectClass mustContain/mayContain per AD 2012 R2.

Revision ID: edb7f2a1c409
Revises: 552b4eafb1aa
Create Date: 2026-04-17

"""

from __future__ import annotations

from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from entities import Attribute, Directory, EntityType
from enums import EntityTypeNames
from ldap_protocol.ldap_schema.object_class.constants import (
    ObjectClassAttributeNames,
)
from ldap_protocol.utils.queries import get_base_directories
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "edb7f2a1c409"
down_revision: None | str = "552b4eafb1aa"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None

_OBJECTSID_MUST_OBJECT_CLASSES: frozenset[str] = frozenset(
    {
        "securityprincipal",
        "user",
        "computer",
        "group",
        "foreignsecurityprincipal",
        "inetorgperson",
        "msds-managedserviceaccount",
        "msds-groupmanagedserviceaccount",
        "mspki-key-recovery-agent",
    },
)

_OBJECTSID_MAY_OBJECT_CLASSES: frozenset[str] = frozenset(
    {
        "domaindns",
        "samdomain",
        "samdomainbase",
        "builtindomain",
    },
)


def upgrade(container: AsyncContainer) -> None:
    """Ensure objectSid in mustContain/mayContain for known classes."""

    async def _patch_object_classes(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        if not await get_base_directories(session):
            return

        targets = sorted(
            _OBJECTSID_MUST_OBJECT_CLASSES | _OBJECTSID_MAY_OBJECT_CLASSES,
        )
        dirs = await session.scalars(
            select(Directory)
            .join(qa(Directory.entity_type))
            .where(
                qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
                func.lower(qa(Directory.name)).in_(targets),
            ),
        )
        oc_dirs = list(dirs.all())
        if not oc_dirs:
            await session.commit()
            return

        oc_ids = [d.id for d in oc_dirs]
        existing = await session.scalars(
            select(Attribute).where(
                qa(Attribute.directory_id).in_(oc_ids),
                qa(Attribute.name).in_(
                    [
                        ObjectClassAttributeNames.ATTRIBUTE_TYPES_MUST,
                        ObjectClassAttributeNames.ATTRIBUTE_TYPES_MAY,
                    ],
                ),
                func.lower(qa(Attribute.value)) == "objectsid",
            ),
        )
        existing_by_dir: dict[int, set[str]] = {}
        for a in existing.all():
            existing_by_dir.setdefault(a.directory_id, set()).add(a.name)

        for oc_dir in oc_dirs:
            name_lower = oc_dir.name.lower()
            wanted = (
                ObjectClassAttributeNames.ATTRIBUTE_TYPES_MUST
                if name_lower in _OBJECTSID_MUST_OBJECT_CLASSES
                else ObjectClassAttributeNames.ATTRIBUTE_TYPES_MAY
            )
            already = existing_by_dir.get(oc_dir.id, set())
            if wanted in already:
                continue
            session.add(
                Attribute(
                    name=wanted,
                    value="objectSid",
                    directory_id=oc_dir.id,
                ),
            )

        await session.commit()

    op.run_async(_patch_object_classes)


def downgrade(container: AsyncContainer) -> None:
    """Remove objectSid mustContain/mayContain rows for these classes."""

    async def _unpatch_object_classes(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)

        if not await get_base_directories(session):
            return

        targets = sorted(
            _OBJECTSID_MUST_OBJECT_CLASSES | _OBJECTSID_MAY_OBJECT_CLASSES,
        )
        oc_dirs = await session.scalars(
            select(qa(Directory.id))
            .join(qa(Directory.entity_type))
            .where(
                qa(EntityType.name) == EntityTypeNames.OBJECT_CLASS,
                func.lower(qa(Directory.name)).in_(targets),
            ),
        )
        oc_ids = list(oc_dirs.all())
        if not oc_ids:
            await session.commit()
            return

        await session.execute(
            delete(Attribute).where(
                qa(Attribute.directory_id).in_(oc_ids),
                qa(Attribute.name).in_(
                    [
                        ObjectClassAttributeNames.ATTRIBUTE_TYPES_MUST,
                        ObjectClassAttributeNames.ATTRIBUTE_TYPES_MAY,
                    ],
                ),
                func.lower(qa(Attribute.value)) == "objectsid",
            ),
        )
        await session.commit()

    op.run_async(_unpatch_object_classes)
