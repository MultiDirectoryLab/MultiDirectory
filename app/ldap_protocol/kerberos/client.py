"""Ready to work kadmin client."""

import backoff
import httpx

import ldap_protocol.kerberos.exceptions as krb_exc

from .base import AbstractKadmin
from .utils import logger_wraps


class KerberosMDAPIClient(AbstractKadmin):
    """KRB server integration."""

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
    async def get_status(self, wait_for_positive: bool = False) -> bool:
        """Get status of setup.

        :param bool wait_for_positive: wait for positive status
        :return bool | None: status or None if max tries achieved
        """
        response = await self.client.get("/setup/status")
        status = response.json()
        if wait_for_positive and not status:
            return False
        return status

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
            raise krb_exc.KRBAPIAddPrincipalError(response.text)

    @logger_wraps()
    async def get_principal(self, name: str) -> dict:
        """Get request."""
        response = await self.client.get("principal", params={"name": name})

        if response.status_code == 404:
            raise krb_exc.KRBAPIPrincipalNotFoundError

        if response.status_code != 200:
            raise krb_exc.KRBAPIGetPrincipalError(response.text)

        return response.json()

    @logger_wraps()
    async def del_principal(self, name: str) -> None:
        """Delete principal."""
        response = await self.client.delete("principal", params={"name": name})

        if response.status_code == 404:
            raise krb_exc.KRBAPIPrincipalNotFoundError

        if response.status_code != 200:
            raise krb_exc.KRBAPIDeletePrincipalError(response.text)

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
            raise krb_exc.KRBAPIChangePasswordError(response.text)

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

        if response.status_code == 404:
            raise krb_exc.KRBAPIPrincipalNotFoundError

        if response.status_code != 201:
            raise krb_exc.KRBAPIChangePasswordError(response.text)

    @logger_wraps()
    async def rename_princ(self, name: str, new_name: str) -> None:
        """Rename request."""
        response = await self.client.put(
            "principal",
            json={"name": name, "new_name": new_name},
        )
        if response.status_code != 202:
            raise krb_exc.KRBAPIRenamePrincipalError(response.text)

    @logger_wraps()
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
            raise krb_exc.KRBAPIPrincipalNotFoundError

        return response

    @logger_wraps()
    async def lock_principal(self, name: str) -> None:
        """Lock princ.

        :param str name: upn
        :raises KRBAPIPrincipalNotFoundError: on error
        :raises KRBAPILockPrincipalError: on error
        """
        response = await self.client.post(
            "principal/lock",
            json={"name": name},
        )

        if response.status_code == 404:
            raise krb_exc.KRBAPIPrincipalNotFoundError

        if response.status_code != 200:
            raise krb_exc.KRBAPILockPrincipalError(response.text)

    @logger_wraps()
    async def force_princ_pw_change(self, name: str) -> None:
        """Force mark password change for principal.

        :param str name: pw
        :raises KRBAPIPrincipalNotFoundError: err
        :raises KRBAPIForcePasswordChangeError: err
        """
        response = await self.client.post(
            "principal/force_reset",
            json={"name": name},
        )

        if response.status_code == 404:
            raise krb_exc.KRBAPIPrincipalNotFoundError

        if response.status_code != 200:
            raise krb_exc.KRBAPIForcePasswordChangeError(response.text)
