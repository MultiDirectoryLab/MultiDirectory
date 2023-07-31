"""Test main config."""

import asyncio
from typing import AsyncGenerator, Generator
from app.ldap.dialogue import Session

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from app.config import Settings
from app.models.database import Base, get_engine


@pytest.fixture(scope="session")
def event_loop(request) -> Generator:  # noqa: indirect usage
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def settings() -> Settings:
    """Get settings."""
    return Settings()


@pytest.fixture(scope="session")
def engine(settings) -> Settings:
    """Get settings."""
    return get_engine(settings)


@pytest_asyncio.fixture(scope="session")
async def migrations(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def session(engine, migrations) -> AsyncGenerator[AsyncSession, None]:
    """Get session and aquire after completion."""
    async_session = sessionmaker(
        engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )

    async with async_session() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture(scope="function")
async def ldap_session() -> AsyncGenerator[Session, None]:
    """Yield empty session."""
    yield Session()
