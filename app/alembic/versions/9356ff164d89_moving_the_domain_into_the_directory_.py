"""Moving the domain into the Directory entity

Revision ID: 9356ff164d89
Revises: 563b850ca7e1
Create Date: 2024-07-31 07:16:21.242262

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import delete, orm, select

from models.ldap3 import CatalogueSetting, Directory, Path
from ldap_protocol.utils import generate_domain_sid, get_domain_attrs


# revision identifiers, used by Alembic.
revision = '9356ff164d89'
down_revision = '563b850ca7e1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    bind = op.get_bind()
    session = orm.Session(bind=bind)

    domain = session.scalar(select(CatalogueSetting).where(
        CatalogueSetting.name == 'defaultNamingContext'))

    if not bool(domain):
        return

    domain = domain.value
    domain_sid = generate_domain_sid()
    base_directory = Directory(
        name=domain,
        object_class='domain',
        object_sid=domain_sid,
    )
    domain_path = [
        f"dc={path}"
        for path in reversed(domain.split('.'))
    ]
    path = Path(path=domain_path, endpoint=base_directory)
    base_directory.paths.append(path)
    session.add_all([base_directory, path])
    session.flush()

    for directory in session.query(Directory).join(Directory.path):
        if directory.is_domain:
            continue

        if not directory.parent_id and not directory.is_domain:
            directory.parent_id = base_directory.id

        if directory.name == 'domain admins':
            directory.object_sid = domain_sid + '-512'
        else:
            directory.object_sid = domain_sid + f'-{1000+directory.id}'

        directory.path.path = path.path + directory.path.path
        directory.depth = len(directory.path.path)

    session.execute(delete(CatalogueSetting).where(
        CatalogueSetting.name == 'defaultNamingContext'))

    session.add_all(get_domain_attrs(base_directory))

    session.commit()

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    bind = op.get_bind()
    session = orm.Session(bind=bind)

    base_directory = session.scalar(select(Directory).where(
        Directory.parent_id.is_(None)))

    if not bool(base_directory):
        return

    len_domain_path = len(base_directory.path.path)

    for directory in session.query(Directory):
        if directory.is_domain:
            continue
        if directory.parent_id == base_directory.id:
            directory.parent_id = None

        directory.depth -= len_domain_path
        directory.path.path = directory.path.path[len_domain_path:]

    session.add(CatalogueSetting(
        name='defaultNamingContext', value=base_directory.name))
    session.delete(base_directory)

    session.commit()

    # ### end Alembic commands ###
