"""Test main config.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import uuid
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, AsyncGenerator, AsyncIterator, Generator, Iterator
from unittest.mock import AsyncMock, Mock

import httpx
import ldap3
import pytest
import pytest_asyncio
import uvloop
from alembic import command
from alembic.config import Config as AlembicConfig
from dishka import (
    AsyncContainer,
    Provider,
    Scope,
    from_context,
    make_async_container,
    provide,
)
from dishka.integrations.fastapi import setup_dishka
from fastapi import FastAPI
from loguru import logger
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker

from app.__main__ import PoolClientHandler
from app.extra import TEST_DATA, setup_enviroment
from config import Settings
from ioc import MFACredsProvider
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.ldap_requests.bind import BindRequest
from ldap_protocol.multifactor import LDAPMultiFactorAPI, MultifactorAPI
from web_app import create_app


class TestProvider(Provider):
    """Test provider."""

    __test__ = False

    scope = Scope.RUNTIME
    settings = from_context(provides=Settings, scope=Scope.RUNTIME)
    _cached_session: AsyncSession | None = None
    _cached_kadmin: Mock | None = None
    _session_id: uuid.UUID | None = None

    @provide(scope=Scope.APP, provides=AbstractKadmin)
    async def get_kadmin(self) -> AsyncIterator[AsyncMock]:
        """Get mock kadmin."""
        kadmin = Mock()

        ok_response = Mock()
        ok_response.status_code = 200
        ok_response.aiter_bytes.return_value = map(bytes, zip(b'test_string'))

        kadmin.setup = AsyncMock()
        kadmin.ktadd = AsyncMock(return_value=ok_response)
        kadmin.get_status = AsyncMock(return_value=False)
        kadmin.add_principal = AsyncMock()
        kadmin.del_principal = AsyncMock()
        kadmin.create_or_update_principal_pw = AsyncMock()

        if not self._cached_kadmin:
            self._cached_kadmin = kadmin

        yield self._cached_kadmin

        self._cached_kadmin = None

    @provide(scope=Scope.RUNTIME, provides=AsyncEngine)
    def get_engine(self, settings: Settings) -> AsyncEngine:
        """Get async engine."""
        return create_async_engine(str(settings.POSTGRES_URI), pool_size=10)

    @provide(scope=Scope.APP, provides=sessionmaker)
    def get_session_factory(
        self, engine: AsyncEngine,
    ) -> sessionmaker:
        """Create session factory."""
        return sessionmaker(
            engine,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
            class_=AsyncSession,
        )

    @provide(scope=Scope.APP, provides=AsyncSession)
    async def get_session(
            self, engine: AsyncEngine,
            session_factory: sessionmaker) -> AsyncIterator[AsyncSession]:
        """Get test session with a savepoint."""
        connection = await engine.connect()
        trans = await connection.begin()
        async_session = session_factory(bind=connection)
        nested = await connection.begin_nested()

        @event.listens_for(async_session.sync_session, "after_transaction_end")
        def end_savepoint(session: AsyncSession, transaction: Any) -> None:
            nonlocal nested

            if not nested.is_active:
                nested =\
                    connection.sync_connection.begin_nested()  # type: ignore

        if self._cached_session is not None:
            pass
        else:
            self._cached_session = async_session

        yield self._cached_session

        self._cached_session = None
        self._session_id = None

        await trans.rollback()
        await async_session.close()
        await connection.close()

    @provide(scope=Scope.SESSION, provides=LDAPSession)
    async def get_ldap_session(self) -> AsyncIterator[LDAPSession]:
        """Create ldap session."""
        return LDAPSession()

    @provide(scope=Scope.REQUEST, provides=MultifactorAPI)
    async def get_mfa_api(self) -> Mock:
        """Create mock mfa."""
        mfa = Mock()
        mfa.ldap_validate_mfa = AsyncMock()
        mfa.get_create_mfa = AsyncMock(return_value="example.com")
        return mfa

    @provide(scope=Scope.REQUEST, provides=LDAPMultiFactorAPI)
    async def get_mfa_ldap_api(self) -> Mock:
        """Create mock mfa."""
        mfa = Mock()
        mfa.ldap_validate_mfa = AsyncMock()
        mfa.get_create_mfa = AsyncMock(return_value="example.com")
        return mfa


@dataclass
class TestCreds:
    """Test credentials class."""

    __test__ = False

    un: str
    pw: str


@pytest.fixture(scope="session")
async def container(settings: Settings) -> AsyncIterator[AsyncContainer]:
    """Create test container."""
    ctnr = make_async_container(
        TestProvider(),
        MFACredsProvider(),
        context={Settings: settings},
        start_scope=Scope.RUNTIME)
    yield ctnr
    await ctnr.close()


class MutePolicyBindRequest(BindRequest):
    """Mute group validaton."""

    __test__ = False

    @staticmethod
    async def is_user_group_valid(*args, **kwargs) -> bool:  # type: ignore
        """Stub."""
        return True


@pytest.fixture()
async def kadmin(container: AsyncContainer) -> AsyncIterator[AbstractKadmin]:
    """Get di kadmin."""
    async with container(scope=Scope.APP) as container:
        yield await container.get(AbstractKadmin)


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


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _migrations(
    container: AsyncContainer,
    settings: Settings,
) -> AsyncGenerator:
    """Run simple migrations."""
    engine = await container.get(AsyncEngine)

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


@pytest_asyncio.fixture(scope="function")
async def session(
    container: AsyncContainer,
    handler: PoolClientHandler,
) -> AsyncIterator[AsyncSession]:
    """Get session and aquire after completion."""
    async with container(scope=Scope.APP) as container:
        session = await container.get(AsyncSession)
        handler.container = container
        yield session


@pytest_asyncio.fixture(scope="function")
async def setup_session(session: AsyncSession) -> None:
    """Get session and aquire after completion."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()


@pytest_asyncio.fixture(scope="function")
async def ldap_session(
        container: AsyncContainer) -> AsyncIterator[LDAPSession]:
    """Yield empty session."""
    async with container(scope=Scope.SESSION) as container:
        yield await container.get(LDAPSession)


@pytest.fixture(scope="session")
async def handler(
    settings: Settings,
    container: AsyncContainer,
) -> AsyncIterator[PoolClientHandler]:
    """Create test handler."""
    async with container(scope=Scope.APP) as app_scope:
        yield PoolClientHandler(settings, app_scope)


@pytest.fixture(scope="session", autouse=True)
def _server(
    event_loop: asyncio.BaseEventLoop,
    handler: PoolClientHandler,
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


@pytest_asyncio.fixture(scope="function")
async def app(
    settings: Settings,
    container: AsyncContainer,
) -> AsyncIterator[FastAPI]:
    """App creator fixture."""
    async with container(scope=Scope.APP) as container:
        app = create_app(settings)
        setup_dishka(container, app)
        yield app


@pytest_asyncio.fixture(scope="function")
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
