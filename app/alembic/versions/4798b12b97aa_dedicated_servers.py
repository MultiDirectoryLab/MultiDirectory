"""Add dedicated servers table.

Revision ID: 4798b12b97aa
Revises: eeaed5989eb0
Create Date: 2025-08-26 12:45:08.370675

"""

import sqlalchemy as sa
from alembic import op
from loguru import logger
from sqlalchemy.orm import Session

from entities import CatalogueSetting, DedicatedServer
from repo.pg.tables import queryable_attr as qa

# revision identifiers, used by Alembic.
revision = "4798b12b97aa"
down_revision = "eeaed5989eb0"
branch_labels: None | str = None
depends_on: None | str = None


def upgrade() -> None:
    """Upgrade."""
    op.create_table(
        "DedicatedServer",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "name",
            sa.String(255),
            nullable=False,
            unique=True,
        ),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("password", sa.String(255), nullable=False),
        sa.Column("base_dn", sa.String(255), nullable=False),
        sa.Column("domain_name", sa.String(255), nullable=False),
        sa.Column("use_tls", sa.Boolean, nullable=False),
        sa.Column("bind_type", sa.String(255), nullable=False),
    )

    bind = op.get_bind()
    session = Session(bind=bind)

    settings_query = sa.select(CatalogueSetting).where(
        qa(CatalogueSetting.name).like("ldap_server_%"),
    )
    settings_records = session.scalars(settings_query)

    for setting in settings_records:
        try:
            name_with_prefix = setting.name
            conn_string = setting.value

            server_name = name_with_prefix.replace("ldap_server_", "", 1)

            schema, conn_part = conn_string.split("://", 1)
            username_password, host_port = conn_part.rsplit("@", 1)
            username, password = username_password.split(":", 1)
            host, port_dn = host_port.split(":", 1)
            port, domain_name_dn = port_dn.split("/", 1)
            base_dn, domain_name = domain_name_dn.split("/", 1)

            use_tls = schema == "ldaps"

            dedicated_server = DedicatedServer(
                name=server_name,
                host=host,
                port=int(port),
                username=username,
                password=password,
                base_dn=base_dn,
                domain_name=domain_name,
                use_tls=use_tls,
                bind_type="SIMPLE",
            )

        except Exception as err:
            logger.error(
                f"Error adding dedicated server: {err}"
                + f" {setting.name=}, {setting.value=}",
            )
            continue
        session.add(dedicated_server)
    session.commit()


def downgrade() -> None:
    """Downgrade."""
    bind = op.get_bind()
    session = Session(bind=bind)

    servers_query = sa.select(DedicatedServer)
    servers_records = session.scalars(servers_query)

    for server in servers_records:
        schema = "ldaps" if server.use_tls else "ldap"
        conn_string = (
            f"{schema}://{server.username}:{server.password}@"
            f"{server.host}:{server.port}/{server.base_dn}/"
            f"{server.domain_name}"
        )

        existing_setting = session.execute(
            sa.select(CatalogueSetting).where(
                qa(CatalogueSetting.name) == f"ldap_server_{server.name}",
            ),
        ).scalar_one_or_none()

        if existing_setting:
            existing_setting.value = conn_string
        else:
            new_setting = CatalogueSetting(
                name=f"ldap_server_{server.name}",
                value=conn_string,
            )
            session.add(new_setting)

    session.commit()

    op.drop_table("DedicatedServer")
