"""nullable user's fields

Revision ID: bed9b4f68539
Revises: 9356ff164d89
Create Date: 2024-08-07 17:13:58.512678

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'bed9b4f68539'
down_revision = '9356ff164d89'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('Users', 'sAMAccountName',
               existing_type=sa.VARCHAR(),
               nullable=True)
    op.alter_column('Users', 'userPrincipalName',
               existing_type=sa.VARCHAR(),
               nullable=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('Users', 'userPrincipalName',
               existing_type=sa.VARCHAR(),
               nullable=False)
    op.alter_column('Users', 'sAMAccountName',
               existing_type=sa.VARCHAR(),
               nullable=False)
    # ### end Alembic commands ###
