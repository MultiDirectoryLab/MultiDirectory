"""Kerberos config server for MultiDirectory integration.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from enum import StrEnum
from functools import wraps
from typing import Any, Callable, NoReturn

import backoff
import httpx
from loguru import logger as loguru_logger
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import Attribute, CatalogueSetting, Directory

KERBEROS_STATE_NAME = "KerberosState"

log = loguru_logger.bind(name="kadmin")

log.add(
    "logs/kadmin_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "kadmin",
    retention="10 days",
    rotation="1d",
    colorize=False,
)


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
                principal = kwargs.get("name", "")

            logger.info(f"Calling{bus_type}'{name}' for {principal}")
            try:
                result = await func(*args, **kwargs)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                logger.critical("Can not access kadmin server!")
                raise KRBAPIError

            except KRBAPIError as err:
                logger.error(f"{name} call raised: {err}")
                raise

            else:
                if not is_stub:
                    logger.success(f"Executed {name}")
            return result

        return wrapped

    return wrapper


class KerberosState(StrEnum):
    """KRB state enum."""

    NOT_CONFIGURED = "0"
    READY = "1"
    WAITING_FOR_RELOAD = "2"


class AbstractKadmin(ABC):
    """Stub client for non set up dirs."""

    client: httpx.AsyncClient

    def __init__(self, client: httpx.AsyncClient) -> None:
        """Set client.

        :param httpx.AsyncClient client: httpx
        """
        self.client = client

    async def setup_configs(
        self,
        krb5_config: str,
        kdc_config: str,
    ) -> None:
        """Request Setup."""
        log.info("Setting up configs")
        response = await self.client.post(
            "/setup/configs",
            json={
                "krb5_config": krb5_config.encode().hex(),
                "kdc_config": kdc_config.encode().hex(),
            },
        )

        if response.status_code != 201:
            raise KRBAPIError(response.text)

    async def setup_stash(
        self,
        domain: str,
        admin_dn: str,
        services_dn: str,
        krbadmin_dn: str,
        krbadmin_password: str,
        admin_password: str,
        stash_password: str,
    ) -> None:
        """Set up stash."""
        log.info("Setting up stash")
        response = await self.client.post(
            "/setup/stash",
            json={
                "domain": domain,
                "admin_dn": admin_dn,
                "services_dn": services_dn,
                "krbadmin_dn": krbadmin_dn,
                "krbadmin_password": krbadmin_password,
                "admin_password": admin_password,
                "stash_password": stash_password,
            },
        )

        if response.status_code != 201:
            raise KRBAPIError(response.text)

    async def setup_subtree(
        self,
        domain: str,
        admin_dn: str,
        services_dn: str,
        krbadmin_dn: str,
        krbadmin_password: str,
        admin_password: str,
        stash_password: str,
    ) -> None:
        """Set up subtree."""
        log.info("Setting up subtree")
        response = await self.client.post(
            "/setup/subtree",
            json={
                "domain": domain,
                "admin_dn": admin_dn,
                "services_dn": services_dn,
                "krbadmin_dn": krbadmin_dn,
                "krbadmin_password": krbadmin_password,
                "admin_password": admin_password,
                "stash_password": stash_password,
            },
        )

        if response.status_code != 201:
            raise KRBAPIError(response.text)

    async def reset_setup(self) -> None:
        """Reset setup."""
        log.warning("Setup reset")
        await self.client.post("/setup/reset")

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
        ldap_keytab_path: str,
    ) -> None:
        """Request Setup."""
        await self.setup_configs(krb5_config, kdc_config)
        await self.setup_stash(
            domain,
            admin_dn,
            services_dn,
            krbadmin_dn,
            krbadmin_password,
            admin_password,
            stash_password,
        )
        await self.setup_subtree(
            domain,
            admin_dn,
            services_dn,
            krbadmin_dn,
            krbadmin_password,
            admin_password,
            stash_password,
        )

        status = await self.get_status(wait_for_positive=True)
        if status:
            await self.ldap_principal_setup(
                f"ldap/{domain}",
                ldap_keytab_path,
            )

    @abstractmethod
    async def add_principal(
        self,
        name: str,
        password: str | None,
        timeout: int | float = 1,
    ) -> None: ...

    @abstractmethod
    async def get_principal(self, name: str) -> dict: ...

    @abstractmethod
    async def del_principal(self, name: str) -> None: ...

    @abstractmethod
    async def change_principal_password(
        self,
        name: str,
        password: str,
    ) -> None: ...

    @abstractmethod
    async def create_or_update_principal_pw(
        self,
        name: str,
        password: str,
    ) -> None: ...

    @abstractmethod
    async def rename_princ(self, name: str, new_name: str) -> None: ...

    @backoff.on_exception(
        backoff.constant,
        (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.RemoteProtocolError,
            ValueError,
        ),
        jitter=None,
        raise_on_giveup=False,
        max_tries=30,
    )
    async def get_status(self, wait_for_positive: bool = False) -> bool | None:
        """Get status of setup.

        :param bool wait_for_positive: wait for positive status
        :return bool | None: status or None if max tries achieved
        """
        response = await self.client.get("/setup/status")
        status = response.json()
        if wait_for_positive and not status:
            raise ValueError
        return status

    @abstractmethod
    async def ktadd(self, names: list[str]) -> httpx.Response: ...

    @abstractmethod
    async def create_or_update_policy(
        self,
        minlife: int,
        maxlife: int,
        minlength: int,
        minclasses: int,
    ) -> None: ...

    @abstractmethod
    async def lock_principal(self, name: str) -> None: ...

    @abstractmethod
    async def force_princ_pw_change(self, name: str) -> None: ...

    async def ldap_principal_setup(self, name: str, path: str) -> None:
        """LDAP principal setup.

        :param str ldap_principal_name: ldap principal name
        :param str ldap_keytab_path: ldap keytab path
        """
        response = await self.client.get("/principal", params={"name": name})
        if response.status_code == 200:
            return

        response = await self.client.post("/principal", json={"name": name})
        if response.status_code != 201:
            log.error(f"Error creating ldap principal: {response.text}")
            return

        response = await self.client.post(
            "/principal/ktadd",
            json=[name],
        )
        if response.status_code != 200:
            log.error(f"Error getting keytab: {response.text}")
            return

        with open(path, "wb") as f:
            f.write(response.read())


class KerberosMDAPIClient(AbstractKadmin):
    """KRB server integration."""

    @logger_wraps(is_stub=True)
    async def setup(*_, **__) -> None:  # type: ignore
        """Stub method, setup is not needed."""

    @logger_wraps()
    async def add_principal(
        self,
        name: str,
        password: str | None,
        timeout: int = 1,
    ) -> None:
        """Add request."""
        response = await self.client.post(
            "principal",
            json={"name": name, "password": password},
            timeout=timeout,
        )

        if response.status_code != 201:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def get_principal(self, name: str) -> dict:
        """Get request."""
        response = await self.client.get("principal", params={"name": name})
        if response.status_code != 200:
            raise KRBAPIError(response.text)

        return response.json()

    @logger_wraps()
    async def del_principal(self, name: str) -> None:
        """Delete principal."""
        response = await self.client.delete("principal", params={"name": name})
        if response.status_code != 200:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def change_principal_password(
        self,
        name: str,
        password: str,
    ) -> None:
        """Change password request."""
        response = await self.client.patch(
            "principal",
            json={"name": name, "password": password},
        )
        if response.status_code != 201:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def create_or_update_principal_pw(
        self,
        name: str,
        password: str,
    ) -> None:
        """Change password request."""
        response = await self.client.post(
            "/principal/create_or_update",
            json={"name": name, "password": password},
        )
        if response.status_code != 201:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def rename_princ(self, name: str, new_name: str) -> None:
        """Rename request."""
        response = await self.client.put(
            "principal",
            json={"name": name, "new_name": new_name},
        )
        if response.status_code != 202:
            raise KRBAPIError(response.text)

    async def ktadd(self, names: list[str]) -> httpx.Response:
        """Ktadd build request for stream and return response.

        :param list[str] names: principals
        :return httpx.Response: stream
        """
        request = self.client.build_request(
            "POST",
            "/principal/ktadd",
            json=names,
        )

        response = await self.client.send(request, stream=True)
        if response.status_code == 404:
            raise KRBAPIError("Principal not found")

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
            "/principal/password_policy",
            json={
                "minlife": minlife,
                "maxlife": maxlife,
                "minlength": minlength,
                "minclasses": minclasses,
            },
        )
        if response.status_code != 200:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def lock_principal(self, name: str) -> None:
        """Lock princ.

        :param str name: upn
        :raises KRBAPIError: on error
        """
        response = await self.client.post(
            "principal/lock",
            json={"name": name},
        )

        if response.status_code != 200:
            raise KRBAPIError(response.text)

    async def force_princ_pw_change(self, name: str) -> None:
        """Force mark password change for principal.

        :param str name: pw
        :raises KRBAPIError: err
        """
        response = await self.client.post(
            "principal/force_reset",
            json={"name": name},
        )

        if response.status_code != 200:
            raise KRBAPIError(response.text)


class StubKadminMDADPIClient(AbstractKadmin):
    """Stub client for non set up dirs."""

    @logger_wraps()
    async def setup(self, *args, **kwargs) -> None:  # type: ignore
        """Call setup."""
        await super().setup(*args, **kwargs)

    @logger_wraps(is_stub=True)
    async def add_principal(
        self,
        name: str,
        password: str | None,
        timeout: int = 1,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def get_principal(self, name: str) -> None: ...

    @logger_wraps(is_stub=True)
    async def del_principal(self, name: str) -> None: ...

    @logger_wraps(is_stub=True)
    async def change_principal_password(
        self,
        name: str,
        password: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def create_or_update_principal_pw(
        self,
        name: str,
        password: str,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def rename_princ(self, name: str, new_name: str) -> None: ...

    @logger_wraps(is_stub=True)
    async def ktadd(self, names: list[str]) -> NoReturn:
        raise KRBAPIError

    @logger_wraps(is_stub=True)
    async def create_or_update_policy(
        self,
        minlife: int,
        maxlife: int,
        minlength: int,
        minclasses: int,
    ) -> None: ...

    @logger_wraps(is_stub=True)
    async def lock_principal(self, name: str) -> None: ...

    @logger_wraps(is_stub=True)
    async def force_princ_pw_change(self, name: str) -> None: ...


async def get_krb_server_state(session: AsyncSession) -> "KerberosState":
    """Get kerberos server state."""
    state = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == KERBEROS_STATE_NAME)
    )  # fmt: skip

    if state is None:
        return KerberosState.NOT_CONFIGURED
    return KerberosState(state.value)


async def set_state(session: AsyncSession, state: "KerberosState") -> None:
    """Set the server state in the database.

    This function updates the server state in the database by either adding
    a new entry, updating an existing entry, or deleting and re-adding the
    entry if there are multiple entries found.
    """
    results = await session.execute(
        select(CatalogueSetting)
        .where(CatalogueSetting.name == KERBEROS_STATE_NAME)
    )  # fmt: skip
    kerberos_state = results.scalar_one_or_none()

    if not kerberos_state:
        session.add(CatalogueSetting(name=KERBEROS_STATE_NAME, value=state))
        return

    await session.execute(
        update(CatalogueSetting)
        .where(CatalogueSetting.name == KERBEROS_STATE_NAME)
        .values(value=state),
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
    subquery = (
        select(Directory.id)
        .where(Directory.name.ilike(name))
        .scalar_subquery()
    )
    await session.execute(
        delete(Attribute)
        .where(
            Attribute.directory_id == subquery,
            Attribute.name == "krbprincipalexpiration",
        )
        .execution_options(synchronize_session=False),
    )
