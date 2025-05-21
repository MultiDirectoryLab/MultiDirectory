"""Attach LDAP entry.

Revision ID: ba78cef9700b
Revises: ba78cef9700a
Create Date: 2025-05-15 11:54:03.712099

"""

from alembic import op
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.ldap_schema.entry_crud import attach_entry_to_directory
from models import Directory

# revision identifiers, used by Alembic.
revision = "ba78cef9700b"
down_revision = "ba78cef9700a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade database schema and data, creating LDAP entries."""

    async def _attach_entry_to_directories(connection) -> None:
        session = AsyncSession(bind=connection)
        session.begin()

        result = await session.execute(
            select(Directory)
            .where(Directory.entry_id.is_(None))
            .options(
                selectinload(Directory.attributes),
                selectinload(Directory.entry),
            )
        )

        for directory in result.scalars().all():
            await attach_entry_to_directory(
                directory=directory,
                session=session,
            )

        await session.commit()  # TODO 123 как унести этот коммит внутрь функции и не закрывать транзакцию?

    op.run_async(_attach_entry_to_directories)


def downgrade() -> None:
    """Downgrade database schema and data back to the previous state."""
