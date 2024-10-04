"""DI Provider MiltiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from typing import AsyncIterator, NewType

import httpx
from dishka import Provider, Scope, from_context, provide
from loguru import logger
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import FallbackAsyncAdaptedQueuePool

from config import Settings
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.dns import (
    AbstractDNSManager,
    DNSManager,
    DNSManagerSettings,
    get_dns_manager_class,
    get_dns_manager_settings,
)
from ldap_protocol.kerberos import AbstractKadmin, get_kerberos_class
from ldap_protocol.multifactor import (
    LDAPMultiFactorAPI,
    MFA_HTTP_Creds,
    MFA_LDAP_Creds,
    MultifactorAPI,
    get_creds,
)

KadminHTTPClient = NewType('KadminHTTPClient', httpx.AsyncClient)
DNSManagerHTTPClient = NewType('DNSManagerHTTPClient', httpx.AsyncClient)
MFAHTTPClient = NewType('MFAHTTPClient', httpx.AsyncClient)


class MainProvider(Provider):
    """Provider for ldap."""

    scope = Scope.APP
    settings = from_context(provides=Settings, scope=Scope.APP)

    @provide(scope=Scope.APP, provides=AsyncEngine)
    def get_engine(self, settings: Settings) -> AsyncEngine:
        """Get async engine."""
        return create_async_engine(
            str(settings.POSTGRES_URI),
            pool_size=settings.INSTANCE_DB_POOL_SIZE,
            max_overflow=settings.INSTANCE_DB_POOL_LIMIT,
            pool_timeout=settings.INSTANCE_DB_POOL_TIMEOUT,
            poolclass=FallbackAsyncAdaptedQueuePool,
            pool_pre_ping=True,
            pool_use_lifo=False,
        )

    @provide(scope=Scope.APP, provides=sessionmaker)
    def get_session_factory(
        self, engine: AsyncEngine,
    ) -> sessionmaker:
        """Create session factory."""
        return sessionmaker(
            engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )

    @provide(scope=Scope.REQUEST, cache=False, provides=AsyncSession)
    async def create_session(
        self, async_session: sessionmaker,
    ) -> AsyncIterator[AsyncSession]:
        """Create session for request."""
        async with async_session() as session:
            yield session
            await session.commit()

    @provide(scope=Scope.SESSION)
    async def get_krb_class(
            self, session_maker: sessionmaker) -> type[AbstractKadmin]:
        """Get kerberos type."""
        async with session_maker() as session:
            return await get_kerberos_class(session)

    @provide(scope=Scope.SESSION)
    async def get_dns_mngr_class(
        self, session_maker: sessionmaker,
    ) -> type[AbstractDNSManager]:
        """Get DNS manager type."""
        async with session_maker() as session:
            return await get_dns_manager_class(session)

    @provide(scope=Scope.REQUEST, provides=DNSManagerSettings)
    async def get_dns_mngr_settings(
        self, session_maker: sessionmaker,
    ) -> 'DNSManagerSettings':
        """Get DNS manager's settings."""
        async with session_maker() as session:
            return await get_dns_manager_settings(session)

    @provide(scope=Scope.APP, provides=KadminHTTPClient)
    async def get_kadmin_http(
            self, settings: Settings) -> AsyncIterator[KadminHTTPClient]:
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

    @provide(scope=Scope.REQUEST, provides=AbstractKadmin)
    async def get_kadmin(
        self, client: KadminHTTPClient,
        kadmin_class: type[AbstractKadmin],
    ) -> AsyncIterator[AbstractKadmin]:
        """Get kadmin class, inherits from AbstractKadmin.

        :param Settings settings: app settings
        :param AsyncSessionMaker session_maker: session maker
        :return AsyncIterator[AbstractKadmin]: kadmin with client
        :yield Iterator[AsyncIterator[AbstractKadmin]]: kadmin
        """
        logger.debug('Initialized kadmin {}', kadmin_class)
        yield kadmin_class(client)
        logger.debug('Closed kadmin {}', kadmin_class)

    @provide(scope=scope.REQUEST, provides=AbstractDNSManager)
    async def get_dns_mngr(
        self,
        settings: DNSManagerSettings,
        dns_manager_class: type[AbstractDNSManager],
    ) -> AsyncIterator[AbstractDNSManager]:
        """Get DNSManager class."""
        yield dns_manager_class(
            settings=settings,
        )


class HTTPProvider(Provider):
    """HTTP LDAP session."""

    scope = Scope.REQUEST

    @provide(provides=LDAPSession)
    async def get_session(self) -> AsyncIterator[LDAPSession]:
        """Create ldap session."""
        return LDAPSession()


class LDAPServerProvider(Provider):
    """Prvider with session scope."""

    scope = Scope.SESSION

    @provide(scope=Scope.SESSION, provides=LDAPSession)
    async def get_session(self) -> AsyncIterator[LDAPSession]:
        """Create ldap session."""
        return LDAPSession()


class MFACredsProvider(Provider):
    """Creds provider."""

    scope = Scope.REQUEST

    @provide(provides=MFA_HTTP_Creds)
    async def get_auth(self, session: AsyncSession) -> MFA_HTTP_Creds | None:
        """Admin creds get.

        :param Annotated[AsyncSession, Depends session: session
        :return MFA_HTTP_Creds: optional creds
        """
        return await get_creds(session, 'mfa_key', 'mfa_secret')

    @provide(provides=MFA_LDAP_Creds)
    async def get_auth_ldap(
            self, session: AsyncSession) -> MFA_LDAP_Creds | None:
        """Admin creds get.

        :param AsyncSession session: db
        :return MFA_LDAP_Creds: optional creds
        """
        return await get_creds(session, 'mfa_key_ldap', 'mfa_secret_ldap')


class MFAProvider(Provider):
    """MFA creds and api provider."""

    scope = Scope.REQUEST

    @provide(provides=MFAHTTPClient)
    async def get_client(self) -> AsyncIterator[MFAHTTPClient]:
        """Get async client for DI."""
        async with httpx.AsyncClient(timeout=4) as client:
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
        if credentials is None:
            return None
        return MultifactorAPI(
            credentials.key,
            credentials.secret, client, settings)

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
        if credentials is None:
            return None
        return LDAPMultiFactorAPI(MultifactorAPI(
            credentials.key,
            credentials.secret, client, settings))
