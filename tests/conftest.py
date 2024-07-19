"""Test main config.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from typing import (
    Annotated,
    Any,
    AsyncGenerator,
    AsyncIterator,
    Generator,
    Iterator,
)

import httpx
import ldap3
import pytest
import pytest_asyncio
import uvloop
from alembic import command
from alembic.config import Config as AlembicConfig
from fastapi import FastAPI
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession
from sqlalchemy.orm import sessionmaker

from api.main.utils import get_kadmin
from app.__main__ import PoolClientHandler
from app.extra import TEST_DATA, setup_enviroment
from config import Settings
from ldap_protocol.dialogue import Session
from ldap_protocol.kerberos import StubKadminMDADPIClient
from ldap_protocol.ldap_requests.bind import BindRequest
from models.database import get_engine
from web_app import create_app, get_session


@dataclass
class TestCreds:
    """Test credentials class."""

    __test__ = False

    un: str
    pw: str


class TestKadminClient(StubKadminMDADPIClient):
    """Test kadmin."""

    __test__ = False

    KTADD_CONTENT = b'test_string'

    args: tuple
    kwargs: dict[str, str | bytes]

    def __init__(self, client: httpx.AsyncClient | None) -> None:
        """Stub init."""

    @classmethod
    @asynccontextmanager
    async def get_krb_ldap_client(
            cls, settings: Settings) -> AsyncIterator['TestKadminClient']:
        """Stub yield."""
        yield cls(None)

    async def setup(self, *args, **kwargs) -> None:  # type: ignore
        """Stub setup."""
        self.args = args
        self.kwargs = kwargs

    def __getattr__(self, name: str) -> Any:
        return super().__getattribute__(name)

    class MuteOkResponse(httpx.Response):
        """Stub response class."""

        status_code: int = 200

        def __init__(self, *args, **kwrgs) -> None:  # type: ignore # noqa
            pass

        async def aiter_bytes(
                self, chunk_size: int | None = None) -> AsyncIterator[bytes]:
            """Stub method, returns KTADD_CONTENT."""
            yield TestKadminClient.KTADD_CONTENT

        async def aclose(self) -> None:
            """Stub."""

    async def ktadd(self, names: list[str]) -> MuteOkResponse:  # noqa
        self.args = (names,)
        return TestKadminClient.MuteOkResponse()

    async def add_principal(self, name: str, password: str) -> None:
        self.args = (name, password)

    async def del_principal(self, name: str) -> None:
        self.args = (name,)

    async def create_or_update_principal_pw(
            self, name: str, password: str) -> None:
        self.args = (name, password)


class TestHandler(PoolClientHandler):  # noqa
    @staticmethod
    def log_addrs(server: asyncio.base_events.Server) -> None:  # noqa
        pass

    @asynccontextmanager
    async def _get_kadmin(self) -> AsyncIterator[TestKadminClient]:
        yield TestKadminClient(None)


class MutePolicyBindRequest(BindRequest):
    """Mute group validaton."""

    __test__ = False

    @staticmethod
    async def is_user_group_valid(*args, **kwargs) -> bool:  # type: ignore
        """Stub."""
        return True


@pytest.fixture()
def kadmin() -> TestKadminClient:  # noqa: indirect usage
    return TestKadminClient(None)


@pytest.fixture(autouse=True)
def _set_kadmin(
        kadmin: TestKadminClient, ldap_session: Session) -> Iterator[None]:
    ldap_session.kadmin = kadmin
    yield
    del ldap_session.kadmin


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
def engine(settings: Settings) -> AsyncEngine:
    """Get settings."""
    return get_engine(settings)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _migrations(
    engine: AsyncEngine,
    settings: Settings,
) -> AsyncGenerator:
    """Run simple migrations."""
    config = AlembicConfig("alembic.ini")
    config.attributes["app_settings"] = settings

    def upgrade(conn: AsyncConnection) -> None:
        config.attributes["connection"] = conn
        command.upgrade(config, "head")

    def downgrade(conn: AsyncConnection) -> None:
        config.attributes["connection"] = conn
        command.downgrade(config, "base")

    async with engine.begin() as conn:
        config.attributes["connection"] = conn
        await conn.run_sync(upgrade)

    yield

    async with engine.begin() as conn:
        await conn.run_sync(downgrade)


@pytest.fixture(scope='session')
def session_factory(
        engine: AsyncEngine) -> Annotated[sessionmaker, AsyncSession]:
    """Create session factory with engine."""
    return sessionmaker(
        engine,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
        class_=AsyncSession,
    )


@asynccontextmanager
async def test_session(
    session_factory: Annotated[sessionmaker, AsyncSession],
    engine: AsyncEngine,
) -> AsyncIterator[AsyncSession]:
    """Create test session."""
    connection = await engine.connect()
    trans = await connection.begin()
    async_session = session_factory(bind=connection)
    nested = await connection.begin_nested()

    @event.listens_for(async_session.sync_session, "after_transaction_end")
    def end_savepoint(session: AsyncSession, transaction: Any) -> None:
        nonlocal nested

        if not nested.is_active:
            nested = connection.sync_connection.begin_nested()  # type: ignore

    yield async_session

    await trans.rollback()
    await async_session.close()
    await connection.close()


@pytest_asyncio.fixture(scope="function")
async def session(
    session_factory: Annotated[sessionmaker, AsyncSession],
    engine: AsyncEngine,
    handler: PoolClientHandler,
    ldap_session: Session,
    app: FastAPI,
) -> AsyncGenerator[AsyncSession, None]:
    """Get session and aquire after completion."""
    async with test_session(session_factory, engine) as session:
        @asynccontextmanager
        async def create_session() -> AsyncIterator[AsyncSession]:
            yield session

        async def get_test_async_session() -> AsyncIterator[AsyncSession]:
            yield session

        # runtime session sync for server and client
        app.dependency_overrides[get_session] = get_test_async_session
        handler.create_session = create_session  # type: ignore

        yield session


@pytest_asyncio.fixture(scope="function")
async def setup_session(session: AsyncSession) -> None:
    """Get session and aquire after completion."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()


@pytest_asyncio.fixture(scope="function")
async def ldap_session(
        settings: Settings,
        kadmin: TestKadminClient) -> AsyncGenerator[Session, None]:
    """Yield empty session."""
    yield Session(settings=settings, kadmin=kadmin)


@pytest.fixture(scope="session")
def handler(settings: Settings) -> TestHandler:
    """Create test handler."""
    return TestHandler(settings)


@pytest.fixture(scope="session", autouse=True)
def _server(
    event_loop: asyncio.BaseEventLoop,
    handler: TestHandler,
) -> Generator:
    """Run server in background."""
    task = asyncio.ensure_future(handler.start(), loop=event_loop)
    event_loop.run_until_complete(asyncio.sleep(.1))
    yield
    with suppress(asyncio.CancelledError):
        task.cancel()


@pytest.fixture()
def ldap_client(settings: Settings) -> ldap3.Connection:
    """Get ldap clinet without a creds."""
    return ldap3.Connection(
        ldap3.Server(str(settings.HOST), settings.PORT, get_info="ALL"))


@pytest.fixture(scope='session')
def app(settings: Settings) -> FastAPI:  # noqa
    return create_app(settings)


@pytest.fixture(autouse=True)
def _override_ldap_session(app: FastAPI, kadmin: TestKadminClient) -> None:
    app.dependency_overrides[get_kadmin] = lambda: kadmin


@pytest_asyncio.fixture(scope='session')
async def http_client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Async client for fastapi tests."""
    async with httpx.AsyncClient(
            transport=httpx.ASGITransport(
                app=app, root_path='/api',  # type: ignore
            ),
            base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture(scope='function')
async def login_headers(
        http_client: httpx.AsyncClient, creds: TestCreds) -> dict:
    """Get ldap clinet without a creds."""
    auth = await http_client.post("auth/token/get", data={
        "username": creds.un, "password": creds.pw})

    return {'Authorization': f"Bearer {auth.json()['access_token']}"}


@pytest.fixture()
def creds(user: dict) -> TestCreds:
    """Get creds from test data."""
    return TestCreds(user['sam_accout_name'], user['password'])


@pytest.fixture()
def user() -> dict:
    """Get user data."""
    return TEST_DATA[1]['children'][0]['organizationalPerson']  # type: ignore


@pytest.fixture()
def _force_override_tls(settings: Settings) -> Iterator:
    """Override tls status for tests."""
    current_status = settings.USE_CORE_TLS
    settings.USE_CORE_TLS = True
    yield
    settings.USE_CORE_TLS = current_status
