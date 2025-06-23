"""Ready to work kadmin client."""

import httpx

from .base import AbstractKadmin, KRBAPIError
from .utils import logger_wraps


class KerberosMDAPIClient(AbstractKadmin):
    """KRB server integration."""

    @logger_wraps(is_stub=True)
    async def setup(*args, **kwargs) -> None:  # type: ignore
        """Stub method, setup is not needed."""

    @logger_wraps()
    async def add_principal(
        self,
        name: str,
        password: str | None,
        timeout: int = 1,
    ) -> None:
        """Add principal.

        Args:
            name (str): principal name
            password (str | None): password
            timeout (int): timeout

        Raises:
            KRBAPIError: API error
        """
        response = await self.client.post(
            "principal",
            json={"name": name, "password": password},
            timeout=timeout,
        )

        if response.status_code != 201:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def get_principal(self, name: str) -> dict:
        """Get principal.

        Args:
            name (str): principal name

        Returns:
            dict

        Raises:
            KRBAPIError: API error
        """
        response = await self.client.get("principal", params={"name": name})
        if response.status_code != 200:
            raise KRBAPIError(response.text)

        return response.json()

    @logger_wraps()
    async def del_principal(self, name: str) -> None:
        """Delete principal.

        Args:
            name (str): principal name

        Raises:
            KRBAPIError: API error
        """
        response = await self.client.delete("principal", params={"name": name})
        if response.status_code != 200:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def change_principal_password(
        self,
        name: str,
        password: str,
    ) -> None:
        """Change principal password.

        Args:
            name (str): principal name
            password: password

        Raises:
            KRBAPIError: API error
        """
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
        """Create or update principal password.

        Args:
            name (str): principal name
            password: password.

        Raises:
            KRBAPIError: API error
        """
        response = await self.client.post(
            "/principal/create_or_update",
            json={"name": name, "password": password},
        )
        if response.status_code != 201:
            raise KRBAPIError(response.text)

    @logger_wraps()
    async def rename_princ(self, name: str, new_name: str) -> None:
        """Rename principal.

        Args:
            name (str): current principal name
            new_name: (str): new principal name

        Raises:
            KRBAPIError: API error
        """
        response = await self.client.put(
            "principal",
            json={"name": name, "new_name": new_name},
        )
        if response.status_code != 202:
            raise KRBAPIError(response.text)

    async def ktadd(self, names: list[str]) -> httpx.Response:
        """Ktadd build request for stream and return response.

        Args:
            names (list[str]): principal names

        Returns:
            httpx.Response: stream

        Raises:
            KRBAPIError: principal not found
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
        """Lock principal.

        Args:
            name (str): user principal name

        Raises:
            KRBAPIError: API error
        """
        response = await self.client.post(
            "principal/lock",
            json={"name": name},
        )

        if response.status_code != 200:
            raise KRBAPIError(response.text)

    async def force_princ_pw_change(self, name: str) -> None:
        """Force mark password change for principal.

        Args:
            name (str): user principal name

        Raises:
            KRBAPIError: API error
        """
        response = await self.client.post(
            "principal/force_reset",
            json={"name": name},
        )

        if response.status_code != 200:
            raise KRBAPIError(response.text)
