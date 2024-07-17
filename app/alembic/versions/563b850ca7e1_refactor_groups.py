"""refactor groups

Revision ID: 563b850ca7e1
Revises: 6355e97cd073
Create Date: 2024-07-05 06:38:42.573067

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import Column, ForeignKey, Integer
from sqlalchemy.orm import declarative_base, Session, selectinload

from models.ldap3 import Directory, DirectoryMembership, Group, User


# revision identifiers, used by Alembic.
revision = '563b850ca7e1'
down_revision = '6355e97cd073'
branch_labels = None
depends_on = None


Base = declarative_base()


class GroupMembership(Base):
    """Group membership - path m2m relationship."""

    __tablename__ = "GroupMemberships"
    group_id = Column('group_id', Integer, primary_key=True)
    group_child_id = Column('group_child_id', Integer, primary_key=True)


class UserMembership(Base):
    """User membership - path m2m relationship."""

    __tablename__ = "UserMemberships"
    group_id = Column('group_id', Integer, primary_key=True)
    user_id = Column('user_id', Integer, primary_key=True)



def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'DirectoryMemberships',
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.Column('directory_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['directory_id'], ['Directory.id'], ),
        sa.ForeignKeyConstraint(['group_id'], ['Groups.id'], ),
        sa.PrimaryKeyConstraint('group_id', 'directory_id')
    )

    bind = op.get_bind()
    session = Session(bind=bind)

    user_directory = {
        user.id: user.directory_id
        for user in session.query(User)
    }
    group_directory = {
        group.id: group.directory_id
        for group in session.query(Group)
    }
    new_table_values = {
        user_directory[member.user_id]: member.group_id
        for member in session.query(UserMembership)
    }
    for group in session.query(GroupMembership):
        new_table_values[group_directory[group.group_child_id]] = group.group_id

    for directory_id, group_id in new_table_values.items():
        session.add(DirectoryMembership(
            directory_id=directory_id, group_id=group_id))

    op.drop_table('Computers')
    op.drop_table('GroupMemberships')
    op.drop_table('UserMemberships')

    session.commit()
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'UserMemberships',
        sa.Column('group_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.ForeignKeyConstraint(['group_id'], ['Groups.id'], name='UserMemberships_group_id_fkey'),
        sa.ForeignKeyConstraint(['user_id'], ['Users.id'], name='UserMemberships_user_id_fkey'),
        sa.PrimaryKeyConstraint('group_id', 'user_id', name='UserMemberships_pkey')
    )
    op.create_table(
        'GroupMemberships',
        sa.Column('group_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('group_child_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.ForeignKeyConstraint(['group_child_id'], ['Groups.id'], name='GroupMemberships_group_child_id_fkey'),
        sa.ForeignKeyConstraint(['group_id'], ['Groups.id'], name='GroupMemberships_group_id_fkey'),
        sa.PrimaryKeyConstraint('group_id', 'group_child_id', name='GroupMemberships_pkey')
    )
    op.create_table(
        'Computers',
        sa.Column('id', sa.INTEGER(), server_default=sa.text('nextval(\'"Computers_id_seq"\'::regclass)'), autoincrement=True, nullable=False),
        sa.Column('directoryId', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.ForeignKeyConstraint(['directoryId'], ['Directory.id'], name='Computers_directoryId_fkey'),
        sa.PrimaryKeyConstraint('id', name='Computers_pkey')
    )
    #  {4: 1, 5: 2, 7: 2, 6: 4}

    bind = op.get_bind()
    session = Session(bind=bind)

    for member in session.query(DirectoryMembership).options(
        selectinload(DirectoryMembership.directory),
        selectinload(DirectoryMembership.directory).selectinload(Directory.group),
        selectinload(DirectoryMembership.directory).selectinload(Directory.user),
    ):
        if member.directory.user is not None:
            session.add(UserMembership(
                user_id=member.directory.user.id, group_id=member.group_id))
        elif member.directory.group is not None:
            session.add(GroupMembership(
                group_id=member.group_id, group_child_id=member.directory.group.id))
        else:
            raise Exception('Incorrect data')

    session.commit()

    op.drop_table('DirectoryMemberships')
    # ### end Alembic commands ###
