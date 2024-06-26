"""Array lw index.

Revision ID: 9fc1aad1b5d0
Revises: c06b41714e1a
Create Date: 2024-03-22 13:49:27.213939

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '9fc1aad1b5d0'
down_revision = 'c06b41714e1a'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.execute(sa.text("""
CREATE OR REPLACE FUNCTION array_lowercase(varchar[]) RETURNS varchar[] AS
$BODY$
SELECT array_agg(q.tag) FROM (
    SELECT btrim(lower(unnest($1)))::varchar AS tag
) AS q;
$BODY$
language sql IMMUTABLE;"""))

    op.execute(sa.text('CREATE INDEX lw_path ON "Paths" USING GIN(array_lowercase("path"));'))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.execute(sa.text('DROP INDEX lw_path;'))
    op.execute(sa.text('DROP FUNCTION array_lowercase;'))
    # ### end Alembic commands ###
