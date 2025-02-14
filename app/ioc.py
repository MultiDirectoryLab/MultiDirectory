"""DI Provider MiltiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncIterator, NewType

import httpx
import redis.asyncio as redis
from dishka import Provider, Scope, from_context, provide
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import FallbackAsyncAdaptedQueuePool

from config import Settings
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.dns import (
    AbstractDNSManager,
    DNSManagerSettings,
    get_dns_manager_class,
    get_dns_manager_settings,
    resolve_dns_server_ip,
)
from ldap_protocol.kerberos import AbstractKadmin, get_kerberos_class
from ldap_protocol.multifactor import (
    Creds,
    LDAPMultiFactorAPI,
    MFA_HTTP_Creds,
    MFA_LDAP_Creds,
    MultifactorAPI,
    get_creds,
)
from ldap_protocol.session_storage import RedisSessionStorage, SessionStorage

SessionStorageClient = NewType("SessionStorageClient", redis.Redis)
KadminHTTPClient = NewType("KadminHTTPClient", httpx.AsyncClient)
MFAHTTPClient = NewType("MFAHTTPClient", httpx.AsyncClient)


class MainProvider(Provider):
    """Provider for ldap."""

    scope = Scope.APP
    settings = from_context(provides=Settings, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def get_engine(self, settings: Settings) -> AsyncEngine:
        """Get async engine."""
        return create_async_engine(
            str(settings.POSTGRES_URI),
            pool_size=settings.INSTANCE_DB_POOL_SIZE,
            max_overflow=settings.INSTANCE_DB_POOL_LIMIT,
            pool_timeout=settings.INSTANCE_DB_POOL_TIMEOUT,
            poolclass=FallbackAsyncAdaptedQueuePool,
            future=True,
            pool_pre_ping=True,
            pool_use_lifo=False,
        )

    @provide(scope=Scope.APP)
    def get_session_factory(
        self,
        engine: AsyncEngine,
    ) -> async_sessionmaker[AsyncSession]:
        """Create session factory."""
        return async_sessionmaker(engine, expire_on_commit=False)

    @provide(scope=Scope.REQUEST)
    async def create_session(
        self,
        async_session: async_sessionmaker[AsyncSession],
    ) -> AsyncIterator[AsyncSession]:
        """Create session for request."""
        async with async_session() as session:
            yield session
            await session.commit()

    @provide(scope=Scope.SESSION)
    async def get_krb_class(
        self,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> type[AbstractKadmin]:
        """Get kerberos type."""
        async with session_maker() as session:
            return await get_kerberos_class(session)

    @provide(scope=Scope.APP)
    async def get_kadmin_http(
        self,
        settings: Settings,
    ) -> AsyncIterator[KadminHTTPClient]:
        """Get kadmin class, inherits from AbstractKadmin.

        :param Settings settings: app settings
        :param AsyncSessionMaker session_maker: session maker
        :return AsyncIterator[AbstractKadmin]: kadmin with client
        :yield Iterator[AsyncIterator[AbstractKadmin]]: kadmin
        """
        limits = httpx.Limits(
            max_connections=settings.KRB5_SERVER_MAX_CONN,
            max_keepalive_connections=settings.KRB5_SERVER_MAX_KEEPALIVE,
        )
        async with httpx.AsyncClient(
            timeout=30,
            verify="/certs/krbcert.pem",
            base_url=str(settings.KRB5_CONFIG_SERVER),
            limits=limits,
        ) as client:
            yield KadminHTTPClient(client)

    @provide(scope=Scope.REQUEST)
    async def get_kadmin(
        self,
        client: KadminHTTPClient,
        kadmin_class: type[AbstractKadmin],
    ) -> AbstractKadmin:
        """Get kadmin class, inherits from AbstractKadmin.

        :param Settings settings: app settings
        :param AsyncSessionMaker session_maker: session maker
        :return AsyncIterator[AbstractKadmin]: kadmin with client
        :yield Iterator[AsyncIterator[AbstractKadmin]]: kadmin
        """
        return kadmin_class(client)

    @provide(scope=Scope.SESSION)
    async def get_dns_mngr_class(
        self,
        session_maker: async_sessionmaker[AsyncSession],
    ) -> type[AbstractDNSManager]:
        """Get DNS manager type."""
        async with session_maker() as session:
            return await get_dns_manager_class(session)

    @provide(scope=Scope.REQUEST)
    async def get_dns_mngr_settings(
        self,
        session_maker: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> DNSManagerSettings:
        """Get DNS manager's settings."""
        resolve_coro = resolve_dns_server_ip(settings.DNS_BIND_HOST)
        async with session_maker() as session:
            return await get_dns_manager_settings(session, resolve_coro)

    @provide(scope=Scope.REQUEST)
    async def get_dns_mngr(
        self,
        settings: DNSManagerSettings,
        dns_manager_class: type[AbstractDNSManager],
    ) -> AsyncIterator[AbstractDNSManager]:
        """Get DNSManager class."""
        yield dns_manager_class(settings=settings)

    @provide(scope=Scope.APP)
    async def get_redis_for_sessions(
        self, settings: Settings
    ) -> AsyncIterator[SessionStorageClient]:
        """Get redis connection."""
        client = redis.Redis.from_url(str(settings.SESSION_STORAGE_URL))

        if not await client.ping():
            raise SystemError("Redis is not available")

        yield SessionStorageClient(client)
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


class HTTPProvider(Provider):
    """HTTP LDAP session."""

    scope = Scope.REQUEST

    @provide(provides=LDAPSession)
    async def get_session(self) -> LDAPSession:
        """Create ldap session."""
        return LDAPSession()


class LDAPServerProvider(Provider):
    """Prvider with session scope."""

    scope = Scope.SESSION

    @provide(scope=Scope.SESSION, provides=LDAPSession)
    async def get_session(self, storage: SessionStorage) -> LDAPSession:
        """Create ldap session."""
        return LDAPSession(storage=storage)


class MFACredsProvider(Provider):
    """Creds provider."""

    scope = Scope.REQUEST

    @provide(provides=MFA_HTTP_Creds)
    async def get_auth(self, session: AsyncSession) -> Creds | None:
        """Admin creds get.

        :param Annotated[AsyncSession, Depends session: session
        :return MFA_HTTP_Creds: optional creds
        """
        return await get_creds(session, "mfa_key", "mfa_secret")

    @provide(provides=MFA_LDAP_Creds)
    async def get_auth_ldap(self, session: AsyncSession) -> Creds | None:
        """Admin creds get.

        :param AsyncSession session: db
        :return MFA_LDAP_Creds: optional creds
        """
        return await get_creds(session, "mfa_key_ldap", "mfa_secret_ldap")


class MFAProvider(Provider):
    """MFA creds and api provider."""

    scope = Scope.REQUEST

    @provide(scope=Scope.APP)
    async def get_client(
        self,
        settings: Settings,
    ) -> AsyncIterator[MFAHTTPClient]:
        """Get async client for DI."""
        async with httpx.AsyncClient(
            timeout=settings.MFA_CONNECT_TIMEOUT_SECONDS,
            limits=httpx.Limits(
                max_connections=settings.MFA_MAX_CONN,
                keepalive_expiry=settings.MFA_MAX_KEEPALIVE,
            ),
        ) as client:
            yield MFAHTTPClient(client)

    @provide(provides=MultifactorAPI)
    async def get_http_mfa(
        self,
        credentials: MFA_HTTP_Creds,
        client: MFAHTTPClient,
        settings: Settings,
    ) -> MultifactorAPI | None:
        """Get api from DI.

        :param httpx.AsyncClient client: httpx client
        :param Creds credentials: creds
        :return MultifactorAPI: mfa integration
        """
        if not credentials or not credentials.key or not credentials.secret:
            return None
        return MultifactorAPI(
            credentials.key,
            credentials.secret,
            client,
            settings,
        )

    @provide(provides=LDAPMultiFactorAPI)
    async def get_ldap_mfa(
        self,
        credentials: MFA_LDAP_Creds,
        client: MFAHTTPClient,
        settings: Settings,
    ) -> LDAPMultiFactorAPI | None:
        """Get api from DI.

        :param httpx.AsyncClient client: httpx client
        :param Creds credentials: creds
        :return MultifactorAPI: mfa integration
        """
        if not credentials or not credentials.key or not credentials.secret:
            return None
        return LDAPMultiFactorAPI(
            MultifactorAPI(
                credentials.key,
                credentials.secret,
                client,
                settings,
            ),
        )
