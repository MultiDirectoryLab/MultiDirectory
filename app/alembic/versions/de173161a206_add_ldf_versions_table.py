"""Add LDF versions table.

Revision ID: de173161a206
Revises: 1b71cafba681
Create Date: 2026-03-26 12:41:47.245225

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer

# revision identifiers, used by Alembic.
revision: None | str = "de173161a206"
down_revision: None | str = "1b71cafba681"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Upgrade."""
    op.create_table(
        "LdfVersions",
        sa.Column("version", sa.String(length=255), nullable=False),
        sa.Column(
            "d_create",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum("SUCCESS", "ERROR", name="ldfversionstatus"),
            nullable=True,
        ),
        sa.PrimaryKeyConstraint("version"),
    )
    op.create_index(
        "ix_LdfVersions_d_create",
        "LdfVersions",
        ["d_create"],
        unique=False,
    )
    op.create_index(
        "ix_LdfVersions_status",
        "LdfVersions",
        ["status"],
        unique=False,
    )


def downgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Downgrade."""
    op.drop_index("ix_LdfVersions_status", table_name="LdfVersions")
    op.drop_index("ix_LdfVersions_d_create", table_name="LdfVersions")
    op.drop_table("LdfVersions")
    op.execute(sa.text("DROP TYPE ldfversionstatus"))
