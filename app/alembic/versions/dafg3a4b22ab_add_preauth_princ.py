"""Add preauth principals.

Revision ID: dafg3a4b22ab
Revises: f68a134a3685
Create Date: 2024-12-20 16:28:24.419163

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm import Session

from extra.alembic_utils import temporary_stub_entity_type_name
from ldap_protocol.kerberos import KERBEROS_STATE_NAME
from models import Attribute, CatalogueSetting, User

# revision identifiers, used by Alembic.
revision = "dafg3a4b22ab"
down_revision = "f68a134a3685"
branch_labels = None
depends_on = None


@temporary_stub_entity_type_name
def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    for user in session.query(User):
        if user.sam_account_name == "krbadmin":
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
                ),
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


def downgrade() -> None:
    """Downgrade."""
    op.drop_index(op.f("ix_Settings_name"), table_name="Settings")
    op.create_index(
        op.f("ix_Settings_name"),
        "Settings",
        ["name"],
        unique=False,
    )
