"""empty message

Revision ID: a195dd146174
Revises: f4a7fde509d4
Create Date: 2024-02-14 12:49:13.753035

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a195dd146174'
down_revision = 'f4a7fde509d4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('Directory', sa.Column('lastLogon', sa.DateTime(timezone=True), nullable=True))
    op.drop_constraint('name_parent_uc', 'Directory', type_='unique')
    op.create_unique_constraint('name_parent_uc', 'Directory', ['parentId', 'name'], postgresql_nulls_not_distinct=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('name_parent_uc', 'Directory', type_='unique')
    op.create_unique_constraint('name_parent_uc', 'Directory', ['parentId', 'name'])
    op.drop_column('Directory', 'lastLogon')
    # ### end Alembic commands ###
