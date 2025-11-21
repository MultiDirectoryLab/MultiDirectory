"""Rename readonly group.

Revision ID: 16a9fa2c1f1e
Revises: df4c52a613e5
Create Date: 2025-11-21 13:50:36.452766

"""

from alembic import op
from sqlalchemy import select, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, selectinload

from entities import Attribute, Directory
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision: None | str = "16a9fa2c1f1e"
down_revision: None | str = "df4c52a613e5"
branch_labels: None | list[str] = None
depends_on: None | list[str] = None


def upgrade() -> None:
    """Upgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    try:
        ro_dir_query = (
            select(Directory)
            .options(
                selectinload(qa(Directory.parent)),
            )
            .where(
                qa(Directory.name) == "readonly domain controllers",
            )
        )  # fmt: skip
        ro_dir = session.scalar(ro_dir_query)

        if not ro_dir:
            return

        ro_dir.name = "read-only"

        ro_dir.create_path(ro_dir.parent)

        session.execute(
            update(Attribute)
            .filter_by(
                name="sAMAccountName",
                directory=ro_dir,
                value="readonly domain controllers",
            )
            .values({"value": ro_dir.name}),
        )

        session.execute(
            update(Attribute)
            .filter_by(
                name="cn",
                directory=ro_dir,
                value="readonly domain controllers",
            )
            .values({"value": ro_dir.name}),
        )

        session.commit()
    except (IntegrityError, DBAPIError):
        pass
    finally:
        session.close()


def downgrade() -> None:
    """Downgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    try:
        ro_dir_query = (
            select(Directory)
            .options(
                selectinload(qa(Directory.parent)),
            )
            .where(
                qa(Directory.name) == "read-only",
            )
        )  # fmt: skip
        ro_dir = session.scalar(ro_dir_query)

        if not ro_dir:
            return

        ro_dir.name = "readonly domain controllers"

        ro_dir.create_path(ro_dir.parent)

        session.execute(
            update(Attribute)
            .filter_by(
                name="sAMAccountName",
                directory=ro_dir,
                value="read-only",
            )
            .values({"value": ro_dir.name}),
        )

        session.execute(
            update(Attribute)
            .filter_by(
                name="cn",
                directory=ro_dir,
                value="read-only",
            )
            .values({"value": ro_dir.name}),
        )

        session.commit()
    except (IntegrityError, DBAPIError):
        pass
    finally:
        session.close()
