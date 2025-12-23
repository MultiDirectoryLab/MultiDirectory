"""Alembic migrations file."""

import asyncio
from logging.config import fileConfig

from alembic import context
from dishka import AsyncContainer, make_async_container
from sqlalchemy import Connection, text
from sqlalchemy.ext.asyncio import AsyncConnection

from config import Settings
from ioc import (
    HTTPProvider,
    MainProvider,
    MFACredsProvider,
    MFAProvider,
    MigrationProvider,
)
from repo.pg.tables import metadata

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = metadata


def run_sync_migrations(
    connection: Connection,
    schema_name: str,
    dishka_container: AsyncContainer,
) -> None:
    """Run sync migrations."""
    if schema_name != "public":
        connection.execute(text(f"SET search_path = {schema_name}, public;"))

    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=True,
        version_table_schema=target_metadata.schema,
    )

    with context.begin_transaction():
        context.run_migrations(container=dishka_container)


async def run_async_migrations(
    settings: Settings,
    dishka_container: AsyncContainer,
) -> None:
    """Run async migrations."""
    connection = await dishka_container.get(AsyncConnection)
    await connection.run_sync(
        run_sync_migrations,
        schema_name=settings.TEST_POSTGRES_SCHEMA,
        dishka_container=dishka_container,
    )


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    conn = context.config.attributes.get("connection", None)
    settings: Settings = context.config.attributes.get(
        "app_settings",
        Settings.from_os(),
    )
    dishka_container = context.config.attributes.get("dishka_container", None)
    if not dishka_container:
        dishka_container = make_async_container(
            MainProvider(),
            MFACredsProvider(),
            MFAProvider(),
            HTTPProvider(),
            MigrationProvider(),
            context={Settings: settings},
        )

    if conn is None:
        asyncio.run(run_async_migrations(settings, dishka_container))
    else:
        run_sync_migrations(
            conn,
            schema_name=settings.TEST_POSTGRES_SCHEMA,
            dishka_container=dishka_container,
        )


run_migrations_online()
