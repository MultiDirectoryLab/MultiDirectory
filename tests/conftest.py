"""Test main config."""

import asyncio
from contextlib import asynccontextmanager, suppress
from typing import AsyncGenerator, Generator

import httpx
import ldap3
import pytest
import pytest_asyncio
import uvloop
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from app.__main__ import PoolClientHandler
from app.config import Settings
from app.ldap_protocol.dialogue import Session
from app.models.database import Base, get_engine
from app.web_app import create_app, get_session


class TestHandler(PoolClientHandler):  # noqa
    @staticmethod
    def log_addrs(server):  # noqa
        pass


@pytest.fixture(scope="session")
def event_loop() -> Generator:  # noqa: indirect usage
    loop = uvloop.new_event_loop()
    yield loop
    with suppress(asyncio.CancelledError, RuntimeError):
        asyncio.gather(*asyncio.tasks.all_tasks(loop)).cancel()
        loop.close()


@pytest.fixture(scope="session")
def settings() -> Settings:
    """Get settings."""
    return Settings(MFA_TIMEOUT_SECONDS=1)


@pytest.fixture(scope="session")
def engine(settings) -> Settings:
    """Get settings."""
    return get_engine(settings)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _migrations(engine):
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
    return sessionmaker(
        engine,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
        class_=AsyncSession,
    )


@asynccontextmanager
async def test_session(session_factory, engine):  # noqa
    connection = await engine.connect()
    trans = await connection.begin()
    async_session = session_factory(bind=connection)
    nested = await connection.begin_nested()

    @event.listens_for(async_session.sync_session, "after_transaction_end")
    def end_savepoint(session, transaction):
        nonlocal nested

        if not nested.is_active:
            nested = connection.sync_connection.begin_nested()

    yield async_session

    await trans.rollback()
    await async_session.close()
    await connection.close()


@pytest_asyncio.fixture(scope="function")
async def session(
    session_factory,
    engine,
    handler,
    app,
) -> AsyncGenerator[AsyncSession, None]:
    """Get session and aquire after completion."""
    async with test_session(session_factory, engine) as session:
        @asynccontextmanager
        async def create_session():
            yield session

        async def get_test_async_session():
            yield session

        # runtime session sync for server and client
        app.dependency_overrides[get_session] = get_test_async_session
        handler.create_session = create_session

        yield session


@pytest_asyncio.fixture(scope="function")
async def ldap_session() -> AsyncGenerator[Session, None]:
    """Yield empty session."""
    yield Session()


@pytest.fixture(scope="session")
def handler(settings):
    """Create test handler."""
    return TestHandler(settings)


@pytest.fixture(scope="session", autouse=True)
def _server(event_loop: asyncio.BaseEventLoop, handler):
    """Run server in background."""
    task = asyncio.ensure_future(handler.start(), loop=event_loop)
    event_loop.run_until_complete(asyncio.sleep(.1))
    yield
    with suppress(asyncio.CancelledError):
        task.cancel()


@pytest.fixture()
def ldap_client(settings: Settings):
    """Get ldap clinet without a creds."""
    return ldap3.Connection(
        ldap3.Server(str(settings.HOST), settings.PORT, get_info=None),
        auto_bind=False,
    )


@pytest.fixture(scope='session')
def app(settings):  # noqa
    return create_app(settings)


@pytest_asyncio.fixture(scope='session')
async def http_client(app):
    """Async client for fastapi tests."""
    async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, root_path='/api'),
            base_url="http://test") as client:
        yield client
