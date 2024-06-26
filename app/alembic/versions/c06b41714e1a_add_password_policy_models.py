"""Add password policy models.

Revision ID: c06b41714e1a
Revises: 0c7bd30b5a24
Create Date: 2024-03-11 14:30:15.370483

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'c06b41714e1a'
down_revision = '0c7bd30b5a24'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('PasswordPolicies',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), server_default='Default Policy', nullable=False),
    sa.Column('password_history_length', sa.Integer(), server_default='4', nullable=False),
    sa.Column('maximum_password_age_days', sa.Integer(), server_default='0', nullable=False),
    sa.Column('minimum_password_age_days', sa.Integer(), server_default='0', nullable=False),
    sa.Column('minimum_password_length', sa.Integer(), server_default='7', nullable=False),
    sa.Column('password_must_meet_complexity_requirements', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.add_column('Directory', sa.Column('password_policy_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'Directory', 'PasswordPolicies', ['password_policy_id'], ['id'])
    op.add_column('Users', sa.Column('password_history', postgresql.ARRAY(sa.String()), server_default='{}', nullable=False))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('Users', 'password_history')
    op.drop_column('Directory', 'password_policy_id')
    op.drop_table('PasswordPolicies')
    # ### end Alembic commands ###
