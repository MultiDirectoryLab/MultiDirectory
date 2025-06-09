"""Abstract Kadmin class for kerberos api server."""

from abc import ABC, abstractmethod
from enum import StrEnum

import backoff
import httpx
from loguru import logger as loguru_logger

KERBEROS_STATE_NAME = "KerberosState"
log = loguru_logger.bind(name="kadmin")

log.add(
    "logs/kadmin_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == "kadmin",
    retention="10 days",
    rotation="1d",
    colorize=False,
)


class KerberosState(StrEnum):
    """KRB state enum."""

    NOT_CONFIGURED = "0"
    READY = "1"
    WAITING_FOR_RELOAD = "2"


class KRBAPIError(Exception):
    """API Error."""


class AbstractKadmin(ABC):
    """Stub client for non set up dirs."""

    client: httpx.AsyncClient

    def __init__(self, client: httpx.AsyncClient) -> None:
        """Set client.

        Args:
            client (httpx.AsyncClient): http async client
        """
        self.client = client

    async def setup_configs(
        self,
        krb5_config: str,
        kdc_config: str,
    ) -> None:
        """Request Setup.

        Args:
            krb5_config (str): config
            kdc_config (str): config

        Raises:
            KRBAPIError: not correct
        """
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
        """Set up stash.

        Args:
            domain (str): domain
            admin_dn (str): admin_dn
            services_dn (str): services_dn
            krbadmin_dn (str): krbadmin_dn
            krbadmin_password (str): krbadmin_password
            admin_password (str): admin_password
            stash_password (str): stash_password

        Raises:
            KRBAPIError: not correct
        """
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
        """Set up subtree.

        Args:
            domain (str): domain
            admin_dn (str): admin_dn
            services_dn (str): services_dn
            krbadmin_dn (str): krbadmin_dn
            krbadmin_password (str): krbadmin_password
            admin_password (str): admin_password
            stash_password (str): stash_password.

        Raises:
            KRBAPIError: not correct
        """
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
        """Request Setup.

        Args:
            domain (str): domain
            admin_dn (str): admin_dn
            services_dn (str): services_dn
            krbadmin_dn (str): krbadmin_dn
            krbadmin_password (str): krbadmin_password
            admin_password (str): admin_password
            stash_password (str): stash_password
            krb5_config (str): krb5_config
            kdc_config (str): kdc_config
            ldap_keytab_path (str): ldap keytab path
        """
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
    async def add_principal(  # noqa: D102
        self,
        name: str,
        password: str | None,
        timeout: float = 1,
    ) -> None: ...

    @abstractmethod
    async def get_principal(self, name: str) -> dict: ...  # noqa: D102

    @abstractmethod
    async def del_principal(self, name: str) -> None: ...  # noqa: D102

    @abstractmethod
    async def change_principal_password(  # noqa: D102
        self,
        name: str,
        password: str,
    ) -> None: ...

    @abstractmethod
    async def create_or_update_principal_pw(  # noqa: D102
        self,
        name: str,
        password: str,
    ) -> None: ...

    @abstractmethod
    async def rename_princ(self, name: str, new_name: str) -> None: ...  # noqa: D102

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

        Args:
            wait_for_positive (bool): wait for positive status\
                (Default value = False)

        Returns:
            bool | None: status or None if max tries achieved

        Raises:
            ValueError: not status
        """
        response = await self.client.get("/setup/status")
        status = response.json()
        if wait_for_positive and not status:
            raise ValueError
        return status

    @abstractmethod
    async def ktadd(self, names: list[str]) -> httpx.Response: ...  # noqa: D102

    @abstractmethod
    async def lock_principal(self, name: str) -> None: ...  # noqa: D102

    @abstractmethod
    async def force_princ_pw_change(self, name: str) -> None: ...  # noqa: D102

    async def ldap_principal_setup(self, name: str, path: str) -> None:
        """LDAP principal setup.

        Args:
            name (str): ldap principal name
            path (str): ldap keytab path
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
