"""Abstract DNS client for DNS server managing.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import abstractmethod

import httpx
from fastapi import status

from ldap_protocol.dns.dto import DNSForwardZoneDTO, DNSMasterZoneDTO, DNSRRSetDTO
from ldap_protocol.dns.exceptions import (
    DNSEntryNotFoundError,
    DNSNotImplementedError,
    DNSNotSupportedError,
    DNSUnavailableError,
    DNSValidationError,
)


class AbstractDNSHTTPClient:
    """Abstract DNS client class."""

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        """Initialize the PowerDNS HTTP client."""
        self._http_client = http_client

    async def _validate_response(self, response: httpx.Response) -> None:
        """Validate the API response."""
        match response.status_code:
            case status.HTTP_400_BAD_REQUEST:
                raise DNSNotSupportedError(response.text or "Bad Request")
            case status.HTTP_404_NOT_FOUND:
                raise DNSEntryNotFoundError(response.text or "Not Found")
            case status.HTTP_422_UNPROCESSABLE_ENTITY:
                raise DNSValidationError(response.text or "Unprocessable Entity")
            case status.HTTP_500_INTERNAL_SERVER_ERROR:
                raise DNSUnavailableError(response.text or "Internal Server Error")


class AbstractDNSMasterHTTPClient(AbstractDNSHTTPClient):
    """Abstract DNS client for master server."""

    @abstractmethod
    async def create_record(self, record: DNSRRSetDTO) -> None:
        raise DNSNotImplementedError

    @abstractmethod
    async def get_records(self, zone_id: str) -> list[DNSRRSetDTO]:
        raise DNSNotImplementedError

    @abstractmethod
    async def update_record(self, record: DNSRRSetDTO) -> None:
        raise DNSNotImplementedError

    @abstractmethod
    async def delete_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        raise DNSNotImplementedError

    @abstractmethod
    async def create_master_zone(self, zone: DNSMasterZoneDTO) -> None:
        raise DNSNotImplementedError

    @abstractmethod
    async def get_master_zones(self) -> list[DNSMasterZoneDTO]:
        raise DNSNotImplementedError

    @abstractmethod
    async def get_master_zone_by_id(self, zone_id: str) -> DNSMasterZoneDTO:
        raise DNSNotImplementedError

    @abstractmethod
    async def update_master_zone(self, zone: DNSMasterZoneDTO) -> None:
        raise DNSNotImplementedError

    @abstractmethod
    async def delete_master_zone(self, zone_id: str) -> None:
        raise DNSNotImplementedError


class AbstractDNSForwardHTTPClient(AbstractDNSHTTPClient):
    """Abstract DNS slient for forward server."""

    @abstractmethod
    async def create_forward_zone(self, zone: DNSForwardZoneDTO) -> None:
        raise DNSNotImplementedError

    @abstractmethod
    async def get_forward_zones(self) -> list[DNSForwardZoneDTO]:
        raise DNSNotImplementedError

    @abstractmethod
    async def update_forward_zone(self, zone: DNSForwardZoneDTO) -> None:
        raise DNSNotImplementedError

    @abstractmethod
    async def delete_forward_zone(self, zone_id: str) -> None:
        raise DNSNotImplementedError
