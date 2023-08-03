"""Test main config."""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from app.__main__ import PoolClientHandler
from app.config import Settings
from app.ldap_protocol.dialogue import Session
from app.models.database import Base, get_engine


@pytest.fixture(scope="session")
def event_loop() -> Generator:  # noqa: indirect usage
    loop = asyncio.new_event_loop()
    yield loop
    asyncio.gather(*asyncio.tasks.all_tasks(loop)).cancel()
    loop.close()


@pytest.fixture(scope="session")
def settings() -> Settings:
    """Get settings."""
    return Settings()


@pytest.fixture(scope="session")
def engine(settings) -> Settings:
    """Get settings."""
    return get_engine(settings)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def migrations(engine):
    """Run simple migrations."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture(scope='session')
def session_factory(engine):
    """Create session factory with engine."""
    yield sessionmaker(
        engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )


@pytest_asyncio.fixture(scope="function")
async def session(session_factory) -> AsyncGenerator[AsyncSession, None]:
    """Get session and aquire after completion."""
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture(scope="function")
async def ldap_session() -> AsyncGenerator[Session, None]:
    """Yield empty session."""
    yield Session()


@pytest.fixture(scope="session", autouse=True)
def server(settings, event_loop: asyncio.BaseEventLoop, session_factory):
    """Run server in background."""
    class TestHandler(PoolClientHandler):
        @asynccontextmanager
        async def create_session(self):
            async with session_factory() as session:
                yield session
                await session.rollback()

        @staticmethod
        def log_addrs(server: asyncio.base_events.Server):
            pass

    task = asyncio.ensure_future(
        TestHandler(settings).start(), loop=event_loop)
    event_loop.run_until_complete(asyncio.sleep(.1))
    yield
    task.cancel()
