"""empty message

Revision ID: 50b2889acfb1
Revises: 7ee82f79e990
Create Date: 2023-10-13 08:25:05.763551

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '50b2889acfb1'
down_revision = '7ee82f79e990'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('PolicyMFAMemberships',
    sa.Column('group_id', sa.Integer(), nullable=False),
    sa.Column('policy_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['group_id'], ['Groups.id'], ),
    sa.ForeignKeyConstraint(['policy_id'], ['Policies.id'], ),
    sa.PrimaryKeyConstraint('group_id', 'policy_id')
    )
    op.add_column('Policies', sa.Column('mfa_status', sa.Enum('DISABLED', 'ENABLED', 'WHITELIST', name='mfaflags'), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('Policies', 'mfa_status')
    op.drop_table('PolicyMFAMemberships')
    # ### end Alembic commands ###
