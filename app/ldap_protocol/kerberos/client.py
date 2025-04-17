"""Ready to work kadmin client."""

import httpx

from .base import AbstractKadmin, KRBAPIError
from .utils import logger_wraps


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
