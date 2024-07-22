"""DI Provider MiltiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from functools import partial, wraps
from ipaddress import IPv4Address, ip_address
from typing import AsyncIterator, Callable, NewType, TypeVar, get_type_hints

import httpx
from dishka import AsyncContainer, Provider, Scope, from_context, provide
from loguru import logger
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker

from config import Settings
from ldap_protocol import LDAPSession
from ldap_protocol.kerberos import AbstractKadmin, get_kerberos_class
from ldap_protocol.multifactor import (
    MFA_HTTP_Creds,
    MFA_LDAP_Creds,
    MultifactorAPI,
    get_creds,
)

KadminHTTPClient = NewType('KadminHTTPClient', httpx.AsyncClient)
MFAHTTPClient = NewType('MFAHTTPClient', httpx.AsyncClient)


class MainProvider(Provider):
    """Provider for ldap."""

    scope = Scope.APP
    settings = from_context(provides=Settings, scope=Scope.APP)

    @provide(scope=Scope.APP, provides=AsyncEngine)
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

    @provide(scope=Scope.APP)
    async def get_krb_class(
            self, session_maker: sessionmaker) -> type[AbstractKadmin]:
        """Get kerberos type."""
        async with session_maker() as session:
            return await get_kerberos_class(session)

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

    @provide(scope=Scope.APP, provides=AbstractKadmin)
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


class LDAPServerProvider(Provider):
    """Prvider with session scope."""

    scope = Scope.SESSION

    reader = from_context(provides=asyncio.StreamReader, scope=Scope.SESSION)
    writer = from_context(provides=asyncio.StreamWriter, scope=Scope.SESSION)

    @provide(scope=Scope.SESSION, provides=LDAPSession)
    async def get_session(self) -> AsyncIterator[LDAPSession]:
        """Create ldap session."""
        return LDAPSession()

    @provide(scope=Scope.SESSION)
    def get_ip(self, writer: asyncio.StreamWriter) -> IPv4Address:
        """Get ip form reader."""
        addr = ':'.join(map(str, writer.get_extra_info('peername')))
        return ip_address(addr.split(':')[0])  # type: ignore


class MFAProvider(Provider):
    """MFA creds and api provider."""

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

        :param Annotated[AsyncSession, Depends session: session
        :return MFA_LDAP_Creds: optional creds
        """
        return await get_creds(session, 'mfa_key_ldap', 'mfa_secret_ldap')

    @provide(provides=MFAHTTPClient)
    async def get_client(self) -> AsyncIterator[MFAHTTPClient]:
        """Get async client for DI."""
        async with httpx.AsyncClient(timeout=4) as client:
            yield MFAHTTPClient(client)

    @provide(provides=MultifactorAPI)
    async def get_creds(
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


T = TypeVar('T', bound=Callable)


async def resolve_deps(*, func: T, container: AsyncContainer) -> T:
    """Provide async dependencies.

    :param T func: Awaitable
    :param AsyncContainer container: IoC container
    :return T: Awaitable
    """
    hints = get_type_hints(func)
    del hints['return']
    kwargs = {}

    for arg_name, hint in hints.items():
        kwargs[arg_name] = await container.get(hint)

    return wraps(func)(partial(func, **kwargs))  # type: ignore
