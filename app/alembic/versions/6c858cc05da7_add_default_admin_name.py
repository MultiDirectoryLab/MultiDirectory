"""Add givenName attribute to users without it.

Revision ID: 6c858cc05da7
Revises: 56082d7ac0d4
Create Date: 2025-12-19 17:26:02.630201

"""

import sqlalchemy as sa
from alembic import op
from dishka import AsyncContainer
from sqlalchemy.orm import Session

from entities import Attribute, User
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "6c858cc05da7"
down_revision: None | str = "56082d7ac0d4"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade(container: AsyncContainer) -> None:  # noqa: ARG001
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    users_without_given_name = session.scalars(
        sa.select(User).where(
            ~sa.exists(
                sa.select(1)
                .where(
                    qa(Attribute.directory_id) == qa(User.directory_id),
                    qa(Attribute.name) == "givenName",
                )
                .select_from(Attribute),
            ),
        ),
    ).all()

    for user in users_without_given_name:
        session.add(
            Attribute(
                directory_id=user.directory_id,
                name="givenName",
                value=user.sam_account_name,
            ),
        )

    session.commit()


def downgrade(container: AsyncContainer) -> None:
    """Downgrade."""
    # Откатывать не нужно
