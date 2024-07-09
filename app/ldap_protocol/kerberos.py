"""Kerberos config server for MultiDirectory integration.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from enum import StrEnum
from functools import wraps
from typing import Any, AsyncIterator, Callable

import httpx
from loguru import logger
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from models import CatalogueSetting

KERBEROS_STATE_NAME = 'KerberosState'


log = logger.bind(name='kadmin')

log.add(
    "logs/kadmin_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == 'kadmin',
    retention="10 days",
    rotation="1d",
    colorize=False)


class KRBAPIError(Exception):
    """API Error."""


def logger_wraps() -> Callable:
    def wrapper(func: Callable) -> Callable:
        name = func.__name__

        @wraps(func)
        async def wrapped(*args: tuple[Any], **kwargs: dict[str, Any]) -> Any:
            logger_ = log.opt(depth=1)
            logger_.info("Entering '{}'", name)
            try:
                result = await func(*args, **kwargs)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                logger_.critical("Can not access kadmin server!")
                raise KRBAPIError
            return result

        return wrapped

    return wrapper


class KerberosState(StrEnum):
    """KRB state enum."""

    NOT_CONFIGURED = '0'
    READY = '1'


class AbstractKadmin(ABC):
    """Stub client for non set up dirs."""

    client: httpx.AsyncClient

    def __init__(self, client: httpx.AsyncClient) -> None:
        """Set client.

        :param httpx.AsyncClient client: httpx
        """
        self.client = client

    async def setup(
        self,
        domain: str,
        admin_dn: str,
        services_dn: str,
        krbadmin_dn: str,
        krbadmin_password: str,
        admin_password: str,
        stash_password: str,
        krb5_config: str,
    ) -> None:
        """Request Setup."""
        response = await self.client.post('setup', json={
            "domain": domain,
            "admin_dn": admin_dn,
            "services_dn": services_dn,
            "krbadmin_dn": krbadmin_dn,
            "krbadmin_password": krbadmin_password,
            "admin_password": admin_password,
            "stash_password": stash_password,
            'krb5_config': krb5_config.encode().hex(),
        })

        if response.status_code != 201:
            raise KRBAPIError(response.text)

    @abstractmethod
    async def add_principal(self, name: str, password: str) -> None: ...  # noqa

    @abstractmethod
    async def get_principal(self, name: str) -> dict: ...  # type: ignore  # noqa

    @abstractmethod
    async def del_principal(self, name: str) -> None: ...  # type: ignore  # noqa

    @abstractmethod
    async def change_principal_password(  # noqa
        self, name: str, password: str) -> None: ...  # noqa

    @abstractmethod
    async def create_or_update_principal_pw(  # noqa
        self, name: str, password: str) -> None: ...  # noqa

    @abstractmethod
    async def rename_princ(self, name: str, new_name: str) -> None: ... # noqa

    @classmethod
    @asynccontextmanager
    async def get_krb_ldap_client(
            cls, settings: Settings) -> AsyncIterator['AbstractKadmin']:
        """Get krb client."""
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
            yield cls(client)


class KerberosMDAPIClient(AbstractKadmin):
    """KRB server integration."""

    @logger_wraps()
    async def add_principal(self, name: str, password: str) -> None:
        """Add request."""
        response = await self.client.post('principal', json={
            'name': name, 'password': password})

        if response.status_code != 201:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def get_principal(self, name: str) -> dict:
        """Get request."""
        response = await self.client.post('principal', data={'name': name})
        if response.status_code != 200:
            raise KRBAPIError(response.text)

        return response.json()

    @logger_wraps()
    async def del_principal(self, name: str) -> None:
        """Delete principal."""
        response = await self.client.delete('principal', params={'name': name})
        log.critical(response.url)
        if response.status_code != 200:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def change_principal_password(
            self, name: str, password: str) -> None:
        """Change password request."""
        response = await self.client.patch('principal', json={
            'name': name, 'password': password})
        if response.status_code != 201:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def create_or_update_principal_pw(
            self, name: str, password: str) -> None:
        """Change password request."""
        response = await self.client.post(
            '/principal/create_or_update', json={
                'name': name, 'password': password})
        if response.status_code != 201:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def rename_princ(self, name: str, new_name: str) -> None:
        """Rename request."""
        response = await self.client.patch('principal', json={
            'name': name, 'new_name': new_name})
        if response.status_code != 200:
            raise KRBAPIError(response.text)


class StubKadminMDADPIClient(AbstractKadmin):
    """Stub client for non set up dirs."""

    async def add_principal(self, name: str, password: str) -> None: ...  # noqa

    async def get_principal(self, name: str) -> None: ...  # type: ignore  # noqa

    async def del_principal(self, name: str) -> None: ...  # type: ignore  # noqa

    async def change_principal_password(  # noqa
        self, name: str, password: str) -> None: ...  # noqa

    async def create_or_update_principal_pw(  # noqa
        self, name: str, password: str) -> None: ...  # noqa

    async def rename_princ(self, name: str, new_name: str) -> None: ... # noqa


async def get_krb_server_state(session: AsyncSession) -> 'KerberosState':
    """Get or create server state."""
    state = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == KERBEROS_STATE_NAME),
    )

    if state is None:
        session.add(
            CatalogueSetting(
                name=KERBEROS_STATE_NAME,
                value=KerberosState.NOT_CONFIGURED,
            ),
        )
        await session.commit()
        return KerberosState.NOT_CONFIGURED
    return state.value


async def set_state(session: AsyncSession, state: 'KerberosState') -> None:
    """Set server state in database."""
    await session.execute(
        update(CatalogueSetting)
        .values({"value": state})
        .where(CatalogueSetting.name == KERBEROS_STATE_NAME),
    )


async def get_kerberos_class(
    session: AsyncSession,
) -> type[AbstractKadmin]:
    """Get kerberos server state.

    :param AsyncSession session: db
    :return type[KerberosMDAPIClient] | type[StubKadminMDADPIClient]: api
    """
    if await get_krb_server_state(session) == KerberosState.READY:
        return KerberosMDAPIClient
    return StubKadminMDADPIClient
