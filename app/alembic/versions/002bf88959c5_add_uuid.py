"""add uuid

Revision ID: 002bf88959c5
Revises: aaa8ca2cb70e
Create Date: 2024-06-04 09:33:55.605030

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002bf88959c5'
down_revision = 'aaa8ca2cb70e'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";')
    op.add_column('Directory',
                  sa.Column('objectGUID',
                            postgresql.UUID(as_uuid=True),
                            server_default=sa.text("uuid_generate_v4()"),
                            nullable=False))
    op.create_index('ix_directory_objectGUID', 'Directory', ['objectGUID'])
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('ix_directory_objectGUID', table_name='Directory')
    op.drop_column('Directory', 'objectGUID')
    # ### end Alembic commands ###
