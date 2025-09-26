"""Alembic migrations file."""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from config import Settings
from models import metadata

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = metadata


def run_sync_migrations(connection: Connection) -> None:
    """Run sync migrations."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=True,
        version_table_schema=target_metadata.schema,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations(settings: Settings) -> None:
    """Run async migrations."""
    engine = create_async_engine(str(settings.POSTGRES_URI))

    async with engine.connect() as connection:
        await connection.run_sync(run_sync_migrations)


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    conn = context.config.attributes.get("connection", None)
    settings = context.config.attributes.get(
        "app_settings",
        Settings.from_os(),
    )

    if conn is None:
        asyncio.run(run_async_migrations(settings))
    else:
        run_sync_migrations(conn)


run_migrations_online()
