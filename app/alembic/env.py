"""Alembic migrations file."""

import asyncio
from logging.config import fileConfig

from alembic import context

from models.database import Base, engine

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def do_run_migrations(connection):
    """Run sync migrations."""
    context.configure(connection=connection,
                      target_metadata=target_metadata,
                      include_schemas=True,
                      version_table_schema=target_metadata.schema)

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)


asyncio.run(run_migrations_online())
