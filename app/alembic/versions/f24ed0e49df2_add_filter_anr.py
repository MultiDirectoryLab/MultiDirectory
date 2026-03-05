"""Extend SearchRequest: add aNR filter.

Revision ID: f24ed0e49df2
Revises: 6303f5c706ec
Create Date: 2025-11-11 08:33:46.685338

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer, Scope
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession
from sqlalchemy.orm import Session

from extra.alembic_utils import temporary_stub_column2
from ldap_protocol.ldap_schema.appendix.attribute_type_appendix.attribute_type_appendix_use_case import (  # noqa: E501
    AttributeTypeUseCaseDeprecated,
)

# revision identifiers, used by Alembic.
revision: None | str = "f24ed0e49df2"
down_revision: None | str = "6303f5c706ec"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


_DEFAULT_ANR_ATTRIBUTE_TYPE_NAMES = (
    "displayName",
    "sAMAccountName",
    "mail",
    "givenName",
    "sn",
    "name",
    "cn",
    "physicalDeliveryOfficeName",
    "proxyAddresses",
)


@temporary_stub_column2("AttributeTypes", "system_flags", sa.Integer())
def upgrade(container: AsyncContainer) -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    op.add_column(
        "AttributeTypes",
        sa.Column("is_included_anr", sa.Boolean(), nullable=True),
    )

    async def _false_all_is_included_anr_deprecated(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            at_type_use_case = await cnt.get(AttributeTypeUseCaseDeprecated)

        await at_type_use_case.false_all_is_included_anr_deprecated()
        await session.flush()

    op.run_async(_false_all_is_included_anr_deprecated)

    op.alter_column("AttributeTypes", "is_included_anr", nullable=False)

    op.alter_column(
        "EntityTypes",
        "object_class_names",
        existing_type=postgresql.ARRAY(sa.VARCHAR()),
        nullable=True,
    )

    async def _update_and_get_migration_f24ed_deprecated(
        connection: AsyncConnection,  # noqa: ARG001
    ) -> None:
        async with container(scope=Scope.REQUEST) as cnt:
            session = await cnt.get(AsyncSession)
            at_type_use_case = await cnt.get(AttributeTypeUseCaseDeprecated)

        len_updated_attrs = len(
            await at_type_use_case.update_and_get_migration_f24ed_deprecated(
                _DEFAULT_ANR_ATTRIBUTE_TYPE_NAMES,
            ),
        )
        if len_updated_attrs != len(_DEFAULT_ANR_ATTRIBUTE_TYPE_NAMES):
            raise ValueError(
                "Not all expected attributes were found in the DB.",
            )

        await session.flush()

    op.run_async(_update_and_get_migration_f24ed_deprecated)

    session.commit()


def downgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Downgrade."""
    op.alter_column(
        "EntityTypes",
        "object_class_names",
        existing_type=postgresql.ARRAY(sa.VARCHAR()),
        nullable=False,
    )
    op.drop_column("AttributeTypes", "is_included_anr")
