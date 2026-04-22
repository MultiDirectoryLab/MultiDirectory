"""HTTP Client for PowerDNS servers.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix import Retort

from ldap_protocol.dns.clients.abstract_client import AbstractDNSHTTPClient
from ldap_protocol.dns.dto import DNSForwardZoneDTO, DNSMasterZoneDTO, DNSRRSetDTO

base_retort = Retort()


class PowerDNSAuthHTTPClient(AbstractDNSHTTPClient):
    """HTTP client for PowerDNS Auth server."""

    async def record_action(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Send request to perform action on DNS record in given zone."""
        response = await self._http_client.patch(f"/zones/{zone_id}", json={"rrsets": [base_retort.dump(record)]})

        await self._validate_response(response)

    async def get_records(self, zone_id: str) -> list[DNSRRSetDTO]:
        """Send request to get all records of given zone."""
        response = await self._http_client.get(f"/zones/{zone_id}")
        await self._validate_response(response)

        zone = base_retort.load(response.json(), DNSMasterZoneDTO)
        return zone.rrsets

    async def create_master_zone(self, zone: DNSMasterZoneDTO) -> None:
        """Send request to create new master zone."""
        response = await self._http_client.post("/zones", json=base_retort.dump(zone))
        await self._validate_response(response)

    async def get_master_zones(self) -> list[DNSMasterZoneDTO]:
        """Send request to get all master zones."""
        response = await self._http_client.get("/zones")
        await self._validate_response(response)

        return base_retort.load(response.json(), list[DNSMasterZoneDTO])

    async def get_master_zone_by_id(self, zone_id: str) -> DNSMasterZoneDTO:
        """Send request to get master zone by ID."""
        response = await self._http_client.get(f"/zones/{zone_id}")
        await self._validate_response(response)

        return base_retort.load(response.json(), DNSMasterZoneDTO)

    async def update_master_zone(self, zone_id: str, zone: DNSMasterZoneDTO) -> None:
        """Send request to update master zone with given ID."""
        response = await self._http_client.put(f"/zones/{zone_id}", json=base_retort.dump(zone))
        await self._validate_response(response)

    async def delete_master_zone(self, zone_id: str) -> None:
        """Send request to delete master zone with given ID."""
        response = await self._http_client.delete(f"/zones/{zone_id}")
        await self._validate_response(response)


class PowerDNSRecursorHTTPClient(AbstractDNSHTTPClient):
    """HTTP client for PowerDNS Recursor server."""

    async def create_forward_zone(self, zone: DNSForwardZoneDTO) -> None:
        """Send request to create forward zone."""
        response = await self._http_client.post("/zones", json=base_retort.dump(zone))
        await self._validate_response(response)

    async def get_forward_zones(self) -> list[DNSForwardZoneDTO]:
        """Send request to get all forward zones."""
        response = await self._http_client.get("/zones")
        await self._validate_response(response)

        return base_retort.load(response.json(), list[DNSForwardZoneDTO])

    async def update_forward_zone(self, zone_id: str, zone: DNSForwardZoneDTO) -> None:
        """Send request to update forward zone with given ID."""
        response = await self._http_client.put(f"/zones/{zone_id}", json=base_retort.dump(zone))
        await self._validate_response(response)

    async def delete_forward_zone(self, zone_id: str) -> None:
        """Send request to delete forward zone with given ID."""
        response = await self._http_client.delete(f"/zones/{zone_id}")
        await self._validate_response(response)
