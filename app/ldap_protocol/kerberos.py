"""Kerberos config server for MultiDirectory integration.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from enum import StrEnum
from functools import wraps
from typing import Any, Callable, NoReturn

import httpx
from loguru import logger as loguru_logger
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import Attribute, CatalogueSetting, Directory

KERBEROS_STATE_NAME = 'KerberosState'

log = loguru_logger.bind(name='kadmin')

log.add(
    "logs/kadmin_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == 'kadmin',
    retention="10 days",
    rotation="1d",
    colorize=False)


class KRBAPIError(Exception):
    """API Error."""


def logger_wraps(is_stub: bool = False) -> Callable:
    """Log kadmin calls.

    :param bool is_stub: flag to change logs, defaults to False
    :return Callable: any method
    """
    def wrapper(func: Callable) -> Callable:
        name = func.__name__
        bus_type = " stub " if is_stub else " "

        @wraps(func)
        async def wrapped(*args: str, **kwargs: str) -> Any:
            logger = log.opt(depth=1)
            try:
                principal = args[1]
            except IndexError:
                principal = kwargs.get('name', '')

            logger.info(f"Calling{bus_type}'{name}' for {principal}")
            try:
                result = await func(*args, **kwargs)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                logger.critical("Can not access kadmin server!")
                raise KRBAPIError

            except KRBAPIError as err:
                logger.error(f'{name} call raised: {err}')
                raise

            else:
                if not is_stub:
                    logger.success(f"Executed {name}")
            return result

        return wrapped

    return wrapper


class KerberosState(StrEnum):
    """KRB state enum."""

    NOT_CONFIGURED = '0'
    READY = '1'
    WAITING_FOR_RELOAD = '2'


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
        kdc_config: str,
    ) -> None:
        """Request Setup."""
        log.info("Setting up configs")
        response = await self.client.post('/setup/configs', json={
            'krb5_config': krb5_config.encode().hex(),
            'kdc_config': kdc_config.encode().hex(),
        })

        if response.status_code != 201:
            raise KRBAPIError(response.text)

        log.info("Setting up stash")
        response = await self.client.post('/setup/stash', json={
            "domain": domain,
            "admin_dn": admin_dn,
            "services_dn": services_dn,
            "krbadmin_dn": krbadmin_dn,
            "krbadmin_password": krbadmin_password,
            "admin_password": admin_password,
            "stash_password": stash_password,
        })

        if response.status_code != 201:
            raise KRBAPIError(response.text)

        log.info("Setting up subtree")
        response = await self.client.post('/setup/subtree', json={
            "domain": domain,
            "admin_dn": admin_dn,
            "services_dn": services_dn,
            "krbadmin_dn": krbadmin_dn,
            "krbadmin_password": krbadmin_password,
            "admin_password": admin_password,
            "stash_password": stash_password,
        })

        if response.status_code != 201:
            raise KRBAPIError(response.text)

    @abstractmethod
    async def add_principal(  # noqa
        self, name: str, password: str | None,
        timeout: int = 1) -> None: ...

    @abstractmethod
    async def get_principal(self, name: str) -> dict: ...  # noqa

    @abstractmethod
    async def del_principal(self, name: str) -> None: ...  # noqa

    @abstractmethod
    async def change_principal_password(  # noqa
        self, name: str, password: str) -> None: ...  # noqa

    @abstractmethod
    async def create_or_update_principal_pw(  # noqa
        self, name: str, password: str) -> None: ...  # noqa

    @abstractmethod
    async def rename_princ(self, name: str, new_name: str) -> None: ... # noqa

    async def get_status(self) -> bool: # noqa
        return False

    @abstractmethod
    async def ktadd(self, names: list[str]) -> httpx.Response: ...  # noqa

    @abstractmethod
    async def create_or_update_policy(  # noqa
        self,
        minlife: int,
        maxlife: int,
        minlength: int,
        minclasses: int,
    ) -> None: ...

    @abstractmethod
    async def lock_principal(self, name: str) -> None: ...  # noqa


class KerberosMDAPIClient(AbstractKadmin):
    """KRB server integration."""

    @logger_wraps(is_stub=True)
    async def setup(*_, **__) -> None:  # type: ignore
        """Stub method, setup is not needed."""

    @logger_wraps()
    async def add_principal(
        self, name: str, password: str | None,
        timeout: int = 1,
    ) -> None:
        """Add request."""
        response = await self.client.post('principal', json={
            'name': name, 'password': password}, timeout=timeout)

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

    async def get_status(self) -> bool: # noqa
        response = await self.client.get('/setup/status')
        return response.json()

    async def ktadd(self, names: list[str]) -> httpx.Response:
        """Ktadd build request for stream and return response.

        :param list[str] names: principals
        :return httpx.Response: stream
        """
        request = self.client.build_request(
            'POST', '/principal/ktadd', json=names)

        response = await self.client.send(request, stream=True)
        if response.status_code == 404:
            raise KRBAPIError('Principal not found')

        return response

    @logger_wraps()
    async def create_or_update_policy(
        self,
        minlife: int,
        maxlife: int,
        minlength: int,
        minclasses: int,
    ) -> None:
        """Create or update pw policy for krb.

        :param int minlife: pw attrs
        :param int maxlife: pw attrs
        :param int minlength: pw attrs
        :param int minclasses: pw attrs
        :raises KRBAPIError: on failure
        """
        response = await self.client.post(
            '/principal/password_policy', json={
                "minlife": minlife,
                "maxlife": maxlife,
                "minlength": minlength,
                "minclasses": minclasses,
            })
        if response.status_code != 200:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def lock_principal(self, name: str) -> None:
        """Lock princ.

        :param str name: upn
        :raises KRBAPIError: on error
        """
        response = await self.client.post(
            'principal/lock', json={'name': name})

        if response.status_code != 200:
            raise KRBAPIError(response.text)


class StubKadminMDADPIClient(AbstractKadmin):
    """Stub client for non set up dirs."""

    @logger_wraps()
    async def setup(self, *args, **kwargs) -> None:  # type: ignore
        """Call setup."""
        await super().setup(*args, **kwargs)

    @logger_wraps(is_stub=True)
    async def add_principal(  # noqa D102
        self, name: str, password: str | None,
        timeout: int = 1,
    ) -> None:
        ...

    @logger_wraps(is_stub=True)
    async def get_principal(self, name: str) -> None:  # noqa D102
        ...

    @logger_wraps(is_stub=True)
    async def del_principal(self, name: str) -> None:  # noqa D102
        ...

    @logger_wraps(is_stub=True)
    async def change_principal_password(  # noqa D102
        self, name: str, password: str,
    ) -> None:  # noqa
        ...

    @logger_wraps(is_stub=True)
    async def create_or_update_principal_pw(  # noqa D102
            self, name: str, password: str) -> None:  # noqa
        ...

    @logger_wraps(is_stub=True)
    async def rename_princ(self, name: str, new_name: str) -> None:  # noqa D102
        ...

    @logger_wraps(is_stub=True)
    async def ktadd(self, names: list[str]) -> NoReturn:  # noqa
        raise KRBAPIError

    @logger_wraps(is_stub=True)
    async def create_or_update_policy(  # noqa
        self,
        minlife: int,
        maxlife: int,
        minlength: int,
        minclasses: int,
    ) -> None:
        ...

    @logger_wraps(is_stub=True)
    async def lock_principal(self, name: str) -> None:  # noqa
        ...


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


async def unlock_principal(name: str, session: AsyncSession) -> None:
    """Unlock principal.

    :param str name: upn
    :param AsyncSession session: db
    """
    subquery = select(Directory.id).where(
        Directory.name.ilike(name)).as_scalar()
    await session.execute(
        delete(Attribute)
        .where(
            Attribute.directory_id == subquery,
            Attribute.name == 'krbprincipalexpiration')
        .execution_options(synchronize_session=False))
