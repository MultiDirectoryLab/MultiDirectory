"""Add preauth principals.

Revision ID: dafg3a4b22ab
Revises: f68a134a3685
Create Date: 2024-12-20 16:28:24.419163

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from ldap_protocol.kerberos import KERBEROS_STATE_NAME
from models import Attribute, CatalogueSetting, User

# revision identifiers, used by Alembic.
revision = "dafg3a4b22ab"
down_revision = "f68a134a3685"
branch_labels = None
depends_on = None


def has_column(table_name: str, column_name: str, bind) -> bool:
    """Check if a column exists in a table."""
    inspector = inspect(bind)
    columns = [col["name"] for col in inspector.get_columns(table_name)]
    return bool(column_name in columns)


def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    if not has_column("Directory", "entry_id", op.get_bind()):
        op.add_column(
            "Directory",
            sa.Column("entry_id", sa.Integer(), nullable=True),
        )

    for user in session.query(User):
        if user.sam_accout_name == "krbadmin":
            continue

        username, domain = user.user_principal_name.split("@")
        principal = f"{username}@{domain.upper()}"

        attr_principal = session.scalar(
            sa.select(Attribute)
            .filter(
                Attribute.name == "krbprincipalname",
                Attribute.value == principal,
            ),
        )  # fmt: skip
        if attr_principal:
            session.add(
                Attribute(
                    name="krbticketflags",
                    value="128",
                    directory_id=attr_principal.directory_id,
                )
            )

    # NOTE: Remove duplicate Kerberos state settings and keep the latest one
    settings = session.scalar(
        sa.select(CatalogueSetting)
        .where(CatalogueSetting.name == KERBEROS_STATE_NAME),
    )  # fmt: skip

    if settings:
        session.execute(
            sa.delete(CatalogueSetting)
            .where(
                CatalogueSetting.name == KERBEROS_STATE_NAME,
                CatalogueSetting.id != settings.id,
            ),
        )  # fmt: skip

        session.commit()

    # NOTE: Set unique constraint on Settings.name
    op.drop_index(op.f("ix_Settings_name"), table_name="Settings")

    op.create_index(
        op.f("ix_Settings_name"),
        "Settings",
        ["name"],
        unique=True,
    )

    if has_column("Directory", "entry_id", op.get_bind()):
        op.drop_column("Directory", "entry_id")


def downgrade() -> None:
    """Downgrade."""
    op.drop_index(op.f("ix_Settings_name"), table_name="Settings")
    op.create_index(
        op.f("ix_Settings_name"),
        "Settings",
        ["name"],
        unique=False,
    )
    if has_column("Directory", "entry_id", op.get_bind()):
        op.drop_column("Directory", "entry_id")
