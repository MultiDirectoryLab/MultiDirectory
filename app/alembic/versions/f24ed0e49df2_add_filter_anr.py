"""Extend SearchRequest: add aNR filter.

Revision ID: f24ed0e49df2
Revises: 6303f5c706ec
Create Date: 2025-11-11 08:33:46.685338

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from entities import AttributeType
from repo.pg.tables import queryable_attr as qa

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


def upgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    op.add_column(
        "AttributeTypes",
        sa.Column("is_included_anr", sa.Boolean(), nullable=True),
    )
    session.execute(
        sa.update(AttributeType).values({"is_included_anr": False}),
    )
    op.alter_column("AttributeTypes", "is_included_anr", nullable=False)

    op.alter_column(
        "EntityTypes",
        "object_class_names",
        existing_type=postgresql.ARRAY(sa.VARCHAR()),
        nullable=True,
    )

    updated_attrs = session.execute(
        sa.update(AttributeType)
        .where(qa(AttributeType.name).in_(_DEFAULT_ANR_ATTRIBUTE_TYPE_NAMES))
        .values({"is_included_anr": True})
        .returning(qa(AttributeType.name)),
    )
    if len(updated_attrs.all()) != len(_DEFAULT_ANR_ATTRIBUTE_TYPE_NAMES):
        raise ValueError("Not all expected attributes were found in the DB.")

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
