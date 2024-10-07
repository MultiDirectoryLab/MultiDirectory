"""Test main config.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import uuid
from contextlib import suppress
from dataclasses import dataclass
from typing import AsyncGenerator, AsyncIterator, Generator, Iterator
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
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import SessionTransaction

from app.__main__ import PoolClientHandler
from app.extra import TEST_DATA, setup_enviroment
from config import Settings
from ioc import MFACredsProvider
from ldap_protocol.access_policy import create_access_policy
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.dns import AbstractDNSManager, DNSManagerSettings, get_dns_manager_settings
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.ldap_requests.bind import BindRequest
from ldap_protocol.multifactor import LDAPMultiFactorAPI, MultifactorAPI
from ldap_protocol.utils.queries import get_user
from models import Directory
from web_app import create_app


class TestProvider(Provider):
    """Test provider."""

    __test__ = False

    scope = Scope.RUNTIME
    settings = from_context(provides=Settings, scope=Scope.RUNTIME)
    _cached_session: AsyncSession | None = None
    _cached_kadmin: Mock | None = None
    _cached_dns_manager: Mock | None = None
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
        kadmin.rename_princ = AsyncMock()
        kadmin.create_or_update_principal_pw = AsyncMock()
        kadmin.change_principal_password = AsyncMock()
        kadmin.create_or_update_policy = AsyncMock()
        kadmin.lock_principal = AsyncMock()

        if not self._cached_kadmin:
            self._cached_kadmin = kadmin

        yield self._cached_kadmin

        self._cached_kadmin = None

    @provide(scope=Scope.REQUEST, provides=AbstractDNSManager)
    async def get_dns_mngr(self) -> AsyncIterator[AsyncMock]:
        """Get mock DNS manager."""
        dns_manager = Mock()

        dns_manager.create_record = AsyncMock()
        dns_manager.update_record = AsyncMock()
        dns_manager.delete_record = AsyncMock()
        dns_manager.get_all_records = AsyncMock(return_value=[{"record_type": "A", "records": [{"hostname": "example.com", "ip": "127.0.0.1", "ttl": 3600}]}])
        dns_manager.setup = AsyncMock()

        if not self._cached_dns_manager:
            self._cached_dns_manager = dns_manager

        yield self._cached_dns_manager

        self._cached_dns_manager = None

    @provide(scope=Scope.REQUEST, provides=DNSManagerSettings, cache=False)
    async def get_dns_mngr_settings(
            self, session_maker: sessionmaker,
    ) -> 'DNSManagerSettings':
        """Get DNS manager's settings."""
        async with session_maker() as session:
            return await get_dns_manager_settings(session)

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

    @provide(scope=Scope.APP, cache=False, provides=AsyncSession)
    async def get_session(
            self, engine: AsyncEngine,
            session_factory: sessionmaker) -> AsyncIterator[AsyncSession]:
        """Get test session with a savepoint."""
        if self._cached_session:
            yield self._cached_session
            return

        connection = await engine.connect()
        trans = await connection.begin()
        async_session = session_factory(bind=connection)
        nested = await connection.begin_nested()

        @event.listens_for(async_session.sync_session, "after_transaction_end")
        def end_savepoint(
            session: AsyncSession,
            transaction: SessionTransaction,
        ) -> None:
            nonlocal nested
            if not nested.is_active:
                nested =\
                    connection.sync_connection.begin_nested()  # type: ignore

        self._cached_session = async_session
        self._session_id = uuid.uuid4()

        yield async_session

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


@pytest_asyncio.fixture(scope="session")
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


@pytest_asyncio.fixture
async def kadmin(container: AsyncContainer) -> AsyncIterator[AbstractKadmin]:
    """Get di kadmin."""
    async with container(scope=Scope.APP) as container:
        yield await container.get(AbstractKadmin)


@pytest_asyncio.fixture
async def dns_manager(container: AsyncContainer)\
        -> AsyncIterator[AbstractDNSManager]:
    """Get DI DNS manager."""
    async with container(scope=Scope.REQUEST) as container:
        yield await container.get(AbstractDNSManager)


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

    domain: Directory = await session.scalar(
        select(Directory)
        .filter(Directory.parent_id.is_(None)),
    )
    await create_access_policy(
        name='Root Access Policy',
        can_add=True,
        can_modify=True,
        can_read=True,
        can_delete=True,
        grant_dn=domain.path_dn,
        groups=["cn=domain admins,cn=groups," + domain.path_dn],
        session=session,
    )
    await session.commit()


@pytest_asyncio.fixture(scope="function")
async def ldap_session(
        container: AsyncContainer) -> AsyncIterator[LDAPSession]:
    """Yield empty session."""
    async with container(scope=Scope.SESSION) as container:
        yield await container.get(LDAPSession)


@pytest_asyncio.fixture(scope="function")
async def ldap_bound_session(
    ldap_session: LDAPSession,
    session: AsyncSession,
    creds: TestCreds,
    setup_session: None,
) -> AsyncIterator[LDAPSession]:
    """Yield bound session."""
    user = await get_user(session, creds.un)
    await ldap_session.set_user(user)
    return ldap_session


@pytest_asyncio.fixture(scope="session")
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


@pytest.fixture
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
async def unbound_http_client(
        app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Get async client for fastapi tests.

    :param FastAPI app: asgi app
    :yield Iterator[AsyncIterator[httpx.AsyncClient]]: yield client
    """
    async with httpx.AsyncClient(
            transport=httpx.ASGITransport(
                app=app, root_path='/api',  # type: ignore
            ),
            base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture(scope="function")
async def http_client(
    unbound_http_client: httpx.AsyncClient,
    creds: TestCreds,
    setup_session: None,
) -> httpx.AsyncClient:
    """Authenticate and return client with cookies.

    :param httpx.AsyncClient unbound_http_client: client w/o cookies
    :param TestCreds creds: creds to authn
    :param None setup_session: just a fixture call
    :return httpx.AsyncClient: bound client with cookies
    """
    response = await unbound_http_client.post("auth/token/get", data={
        "username": creds.un, "password": creds.pw})

    assert response.status_code == 200
    assert unbound_http_client.cookies.get('access_token')

    return unbound_http_client


@pytest.fixture
def creds(user: dict) -> TestCreds:
    """Get creds from test data."""
    return TestCreds(user['sam_accout_name'], user['password'])


@pytest.fixture
def user() -> dict:
    """Get user data."""
    return TEST_DATA[1]['children'][0]['organizationalPerson']  # type: ignore


@pytest.fixture
def _force_override_tls(settings: Settings) -> Iterator:
    """Override tls status for tests."""
    current_status = settings.USE_CORE_TLS
    settings.USE_CORE_TLS = True
    yield
    settings.USE_CORE_TLS = current_status
