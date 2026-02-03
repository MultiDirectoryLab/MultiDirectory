"""HTTP Client for PowerDNS servers.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import httpx

from ldap_protocol.dns.clients.abstract_client import AbstractDNSHTTPClient


# TODO: сделать для каждой операции свою ручку
class PowerDNSAuthHTTPClient(AbstractDNSHTTPClient):
    """HTTP client for PowerDNS Auth server."""

    async def send(
        self,
        method: str,
        url: str,
        payload: dict | None = None,
    ) -> httpx.Response:
        """Get the recursor DNS HTTP client."""
        response = await self._http_client.request(
            method=method,
            url=url,
            json=payload,
        )

        await self._validate_response(response)

        return response


class PowerDNSRecursorHTTPClient(AbstractDNSHTTPClient):
    """HTTP client for PowerDNS Recursor server."""

    async def send(
        self,
        method: str,
        url: str,
        payload: dict | None = None,
    ) -> httpx.Response:
        """Get the recursor DNS HTTP client."""
        response = await self._http_client.request(
            method=method,
            url=url,
            json=payload,
        )

        await self._validate_response(response)

        return response
