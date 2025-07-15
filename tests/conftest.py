"""Test main config.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import uuid
import weakref
from contextlib import suppress
from dataclasses import dataclass
from typing import AsyncGenerator, AsyncIterator, Generator, Iterator
from unittest.mock import AsyncMock, Mock

import aioldap3
import httpx
import pytest
import pytest_asyncio
import redis.asyncio as redis
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
from multidirectory import _create_basic_app
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from api import shadow_router
from api.auth.adapters import IdentityFastAPIAdapter, MFAFastAPIAdapter
from config import Settings
from extra import TEST_DATA, setup_enviroment
from ioc import MFACredsProvider, SessionStorageClient
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.dns import (
    AbstractDNSManager,
    DNSManagerSettings,
    StubDNSManager,
    get_dns_manager_settings,
)
from ldap_protocol.identity import IdentityManager, MFAManager
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.ldap_requests.bind import BindRequest
from ldap_protocol.ldap_schema.attribute_type_dao import AttributeTypeDAO
from ldap_protocol.ldap_schema.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.object_class_dao import ObjectClassDAO
from ldap_protocol.multifactor import LDAPMultiFactorAPI, MultifactorAPI
from ldap_protocol.policies.access_policy import create_access_policy
from ldap_protocol.server import PoolClientHandler
from ldap_protocol.session_storage import RedisSessionStorage, SessionStorage
from ldap_protocol.utils.queries import get_user
from models import Directory


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
        ok_response.aiter_bytes.return_value = map(bytes, zip(b"test_string"))

        kadmin.setup = AsyncMock()
        kadmin.ktadd = AsyncMock(return_value=ok_response)
        kadmin.get_status = AsyncMock(return_value=False)
        kadmin.add_principal = AsyncMock()
        kadmin.del_principal = AsyncMock()
        kadmin.rename_princ = AsyncMock()
        kadmin.create_or_update_principal_pw = AsyncMock()
        kadmin.change_principal_password = AsyncMock()
        kadmin.lock_principal = AsyncMock()
        kadmin.reset_setup = AsyncMock()

        if not self._cached_kadmin:
            self._cached_kadmin = kadmin

        yield self._cached_kadmin

        self._cached_kadmin = None

    @provide(scope=Scope.REQUEST, provides=AbstractDNSManager)
    async def get_dns_mngr(self) -> AsyncIterator[AsyncMock]:
        """Get mock DNS manager."""
        dns_manager = AsyncMock(spec=StubDNSManager)

        dns_manager.get_all_records.return_value = [
            {
                "type": "A",
                "records": [
                    {
                        "name": "example.com",
                        "value": "127.0.0.1",
                        "ttl": 3600,
                    },
                ],
            },
        ]
        dns_manager.get_server_options.return_value = [
            {
                "name": "dnssec-validation",
                "value": "no",
            },
        ]
        dns_manager.get_forward_zones.return_value = [
            {
                "name": "test.local",
                "type": "forward",
                "forwarders": [
                    "127.0.0.1",
                    "127.0.0.2",
                ],
            },
        ]
        dns_manager.get_all_zones_records.return_value = [
            {
                "name": "test.local",
                "type": "master",
                "records": [
                    {
                        "type": "A",
                        "records": [
                            {
                                "name": "example.com",
                                "value": "127.0.0.1",
                                "ttl": 3600,
                            },
                        ],
                    },
                ],
            },
        ]

        if not self._cached_dns_manager:
            self._cached_dns_manager = dns_manager

        yield self._cached_dns_manager

        self._cached_dns_manager = None

    @provide(scope=Scope.REQUEST, provides=DNSManagerSettings, cache=False)
    async def get_dns_mngr_settings(
        self,
        session: AsyncSession,
    ) -> AsyncIterator["DNSManagerSettings"]:
        """Get DNS manager's settings."""

        async def resolve() -> str:
            return "127.0.0.1"

        resolver = resolve()
        yield await get_dns_manager_settings(session, resolver)
        weakref.finalize(resolver, resolver.close)

    @provide(scope=Scope.REQUEST, provides=AttributeTypeDAO, cache=False)
    def get_attribute_type_dao(
        self,
        session: AsyncSession,
    ) -> AttributeTypeDAO:
        """Get Attribute Type DAO."""
        return AttributeTypeDAO(session)

    @provide(scope=Scope.REQUEST, provides=ObjectClassDAO, cache=False)
    def get_object_class_dao(
        self,
        session: AsyncSession,
    ) -> ObjectClassDAO:
        """Get Object Class DAO."""
        attribute_type_dao = AttributeTypeDAO(session)
        return ObjectClassDAO(
            attribute_type_dao=attribute_type_dao,
            session=session,
        )

    get_entity_type_dao = provide(
        EntityTypeDAO,
        scope=Scope.REQUEST,
        cache=False,
    )

    @provide(scope=Scope.RUNTIME, provides=AsyncEngine)
    def get_engine(self, settings: Settings) -> AsyncEngine:
        """Get async engine."""
        return create_async_engine(str(settings.POSTGRES_URI), pool_size=10)

    @provide(scope=Scope.APP, provides=async_sessionmaker[AsyncSession])
    def get_session_factory(
        self,
        engine: AsyncEngine,
    ) -> async_sessionmaker[AsyncSession]:
        """Create session factory."""
        return async_sessionmaker(
            engine,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )

    @provide(scope=Scope.APP, cache=False)
    async def get_session(
        self,
        engine: AsyncEngine,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> AsyncIterator[AsyncSession]:
        """Get test session with a savepoint."""
        if self._cached_session:
            yield self._cached_session
            return

        connection = await engine.connect()
        trans = await connection.begin()

        async_session = session_factory(
            bind=connection,
            info={"mode": "test_transaction"},
            join_transaction_mode="create_savepoint",
        )

        self._cached_session = async_session
        self._session_id = uuid.uuid4()

        yield async_session

        self._cached_session = None
        self._session_id = None

        async_session.expire_all()
        await trans.rollback()
        await async_session.close()
        await connection.close()

    @provide(scope=Scope.SESSION)
    async def get_ldap_session(
        self,
        storage: SessionStorage,
    ) -> AsyncIterator[LDAPSession]:
        """Create ldap session."""
        yield LDAPSession(storage=storage)
        return

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

    @provide(scope=Scope.APP)
    async def get_redis_for_sessions(
        self,
        settings: Settings,
    ) -> AsyncIterator[SessionStorageClient]:
        """Get redis connection."""
        client = redis.Redis.from_url(str(settings.SESSION_STORAGE_URL))

        if not await client.ping():
            raise SystemError("Redis is not available")

        yield SessionStorageClient(client)

        await client.flushdb()
        with suppress(RuntimeError):
            await client.aclose()

    @provide(scope=Scope.APP)
    async def get_session_storage(
        self,
        client: SessionStorageClient,
        settings: Settings,
    ) -> SessionStorage:
        """Get session storage."""
        return RedisSessionStorage(
            client,
            settings.SESSION_KEY_LENGTH,
            settings.SESSION_KEY_EXPIRE_SECONDS,
        )

    identity_fastapi_adapter = provide(
        IdentityFastAPIAdapter,
        scope=Scope.REQUEST,
    )

    identity_manager = provide(
        IdentityManager,
        scope=Scope.REQUEST,
    )

    @provide(scope=Scope.REQUEST)
    def get_mfa_manager(
        self,
        session: AsyncSession,
        settings: Settings,
        storage: SessionStorage,
        mfa_api: MultifactorAPI,
    ) -> MFAFastAPIAdapter:
        """Get MFA manager for tests."""
        return MFAFastAPIAdapter(
            MFAManager(session, settings, storage, mfa_api)
        )


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
        start_scope=Scope.RUNTIME,
    )
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


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create uvloop event loop."""
    loop = uvloop.new_event_loop()
    yield loop
    with suppress(asyncio.CancelledError, RuntimeError):
        asyncio.gather(*asyncio.tasks.all_tasks(loop)).cancel()
        loop.close()


@pytest.fixture(scope="session")
def settings() -> Settings:
    """Get settings."""
    return Settings.from_os()


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
        await conn.run_sync(upgrade)  # type: ignore

    yield

    async with engine.begin() as conn:
        await conn.run_sync(downgrade)  # type: ignore


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

    domain_ex = await session.scalars(
        select(Directory)
        .filter(Directory.parent_id.is_(None)),
    )  # fmt: skip

    domain = domain_ex.one()

    await create_access_policy(
        name="Root Access Policy",
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
    container: AsyncContainer,
) -> AsyncIterator[LDAPSession]:
    """Yield empty session."""
    async with container(scope=Scope.SESSION) as container:
        yield await container.get(LDAPSession)


@pytest_asyncio.fixture(scope="function")
async def ldap_bound_session(
    ldap_session: LDAPSession,
    session: AsyncSession,
    creds: TestCreds,
    setup_session: None,  # noqa: ARG001
) -> AsyncIterator[LDAPSession]:
    """Yield bound session."""
    user = await get_user(session, creds.un)
    assert user
    await ldap_session.set_user(user)
    yield ldap_session
    return


@pytest_asyncio.fixture(scope="session")
async def handler(
    settings: Settings,
    container: AsyncContainer,
) -> AsyncIterator[PoolClientHandler]:
    """Create test handler."""
    async with container(scope=Scope.APP) as app_scope:
        yield PoolClientHandler(settings, app_scope)


@pytest_asyncio.fixture(scope="function")
async def entity_type_dao(
    container: AsyncContainer,
) -> AsyncIterator[EntityTypeDAO]:
    """Get session and aquire after completion."""
    async with container(scope=Scope.APP) as container:
        session = await container.get(AsyncSession)
        yield EntityTypeDAO(session)


@pytest.fixture(scope="session", autouse=True)
def _server(
    event_loop: asyncio.BaseEventLoop,
    handler: PoolClientHandler,
) -> Generator:
    """Run server in background."""
    task = asyncio.ensure_future(handler.start(), loop=event_loop)
    event_loop.run_until_complete(asyncio.sleep(0.1))
    yield
    with suppress(asyncio.CancelledError):
        task.cancel()


@pytest.fixture
async def ldap_client(
    settings: Settings,
    creds: TestCreds,
) -> AsyncIterator[aioldap3.LDAPConnection]:
    """Get LDAP client without credentials."""
    conn = aioldap3.LDAPConnection(
        aioldap3.Server(host=str(settings.HOST), port=settings.PORT)
    )
    await conn.bind(creds.un, creds.pw)
    yield conn
    await conn.unbind()


@pytest.fixture
async def anonymous_ldap_client(
    settings: Settings,
) -> AsyncIterator[aioldap3.LDAPConnection]:
    """Get LDAP client without credentials."""
    conn = aioldap3.LDAPConnection(
        aioldap3.Server(host=str(settings.HOST), port=settings.PORT)
    )
    await conn.bind()
    yield conn
    await conn.unbind()


@pytest_asyncio.fixture(scope="function")
async def app(
    settings: Settings,
    container: AsyncContainer,
) -> AsyncIterator[FastAPI]:
    """App creator fixture."""
    async with container(scope=Scope.APP) as container:
        app = _create_basic_app(settings)
        app.include_router(shadow_router, prefix="/shadow")
        setup_dishka(container, app)
        yield app


@pytest_asyncio.fixture(scope="function")
async def unbound_http_client(
    app: FastAPI,
) -> AsyncIterator[httpx.AsyncClient]:
    """Get async client for fastapi tests.

    :param FastAPI app: asgi app
    :yield Iterator[AsyncIterator[httpx.AsyncClient]]: yield client
    """
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, root_path="/api"),
        timeout=3,
        base_url="http://test",
    ) as client:
        yield client


@pytest_asyncio.fixture(scope="function")
async def http_client(
    unbound_http_client: httpx.AsyncClient,
    creds: TestCreds,
    setup_session: None,  # noqa: ARG001
) -> httpx.AsyncClient:
    """Authenticate and return client with cookies.

    :param httpx.AsyncClient unbound_http_client: client w/o cookies
    :param TestCreds creds: creds to authn
    :param None setup_session: just a fixture call
    :return httpx.AsyncClient: bound client with cookies
    """
    response = await unbound_http_client.post(
        "auth/",
        data={"username": creds.un, "password": creds.pw},
    )

    assert response.status_code == 200
    assert unbound_http_client.cookies.get("id")

    return unbound_http_client


@pytest.fixture
def creds(user: dict) -> TestCreds:
    """Get creds from test data."""
    return TestCreds(user["sam_accout_name"], user["password"])


@pytest.fixture
def user() -> dict:
    """Get user data."""
    return TEST_DATA[1]["children"][0]["organizationalPerson"]  # type: ignore


@pytest.fixture
def _force_override_tls(settings: Settings) -> Iterator:
    """Override tls status for tests."""
    current_status = settings.USE_CORE_TLS
    settings.USE_CORE_TLS = True
    yield
    settings.USE_CORE_TLS = current_status


@pytest_asyncio.fixture
async def dns_manager(
    container: AsyncContainer,
) -> AsyncIterator[AbstractDNSManager]:
    """Get DI DNS manager."""
    async with container(scope=Scope.REQUEST) as container:
        yield await container.get(AbstractDNSManager)


@pytest.fixture
async def storage(container: AsyncContainer) -> AsyncIterator[SessionStorage]:
    """Return session storage."""
    async with container() as c:
        yield await c.get(SessionStorage)
