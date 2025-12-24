"""PowerDNS API manager module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from ipaddress import IPv4Address, IPv6Address

import dns.asyncresolver
import httpx
from adaptix import Retort

from .base import (
    AbstractDNSManager,
    DNSForwarderServerStatus,
    DNSForwardServerStatus,
    DNSManagerSettings,
)
from .constants import DNS_FIRST_SETUP_RECORDS
from .dto import (
    DNSRecordDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
    DNSZoneBaseDTO,
    DNSZoneForwardDTO,
    DNSZoneMasterDTO,
)
from .enums import DNSRecordType, PowerDNSRecordChangeType
from .exceptions import (
    DNSEntryNotFoundError,
    DNSNotSupportedError,
    DNSRecordCreateError,
    DNSRecordDeleteError,
    DNSRecordUpdateError,
    DNSSetupError,
    DNSUnavailableError,
    DNSValidationError,
    DNSZoneCreateError,
    DNSZoneDeleteError,
    DNSZoneUpdateError,
)
from .utils import get_new_zone_records

base_retort = Retort()


class PowerDNSManager(AbstractDNSManager):
    """Manager for interacting with the PowerDNS API."""

    _client_authoritative: httpx.AsyncClient
    _client_recursor: httpx.AsyncClient

    def __init__(
        self,
        settings: DNSManagerSettings,
        client_authoritative: httpx.AsyncClient,
        client_recursor: httpx.AsyncClient,
    ) -> None:
        """Initialize the PowerDNS API repository."""
        super().__init__(settings)
        self._client_authoritative = client_authoritative
        self._client_recursor = client_recursor

    async def _validate_response(self, response: httpx.Response) -> None:
        """Validate the API response."""
        match response.status_code:
            case 400:
                raise DNSNotSupportedError(
                    response.text or "Bad Request",
                )
            case 404:
                raise DNSEntryNotFoundError(
                    response.text or "Not Found",
                )
            case 422:
                raise DNSValidationError(
                    response.text or "Unprocessable Entity",
                )
            case 500:
                raise DNSUnavailableError(
                    response.text or "Internal Server Error",
                )

    async def setup(
        self,
        dns_server_settings: DNSSettingsDTO,
    ) -> None:
        """Set up DNS server and DNS manager."""
        records = []

        for record in DNS_FIRST_SETUP_RECORDS:
            records.append(
                DNSRRSetDTO(
                    name=f"{record['name']}{dns_server_settings.domain}.",
                    type=DNSRecordType(record["type"]),
                    records=[
                        DNSRecordDTO(
                            content=f"{record['value']}{dns_server_settings.domain}.",
                            disabled=False,
                            modified_at=None,
                        ),
                    ],
                    changetype=PowerDNSRecordChangeType.EXTEND,
                    ttl=3600,
                ),
            )

        try:
            await self.create_zone(
                DNSZoneMasterDTO(
                    id=dns_server_settings.domain,
                    name=dns_server_settings.domain,
                    dnssec=False,
                    rrsets=records,
                ),
            )
        except DNSZoneCreateError as e:
            raise DNSSetupError(
                f"Failed to set up DNS: {e}",
            )

    async def create_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Create a DNS record in the specified zone."""
        if not record.name.endswith("."):
            record.name += "."

        record.changetype = PowerDNSRecordChangeType.REPLACE

        response = await self._client_authoritative.patch(
            f"/zones/{zone_id}",
            json={"rrsets": [base_retort.dump(record)]},
        )

        try:
            await self._validate_response(response)
        except httpx.HTTPError as e:
            raise DNSRecordCreateError(
                f"Failed to create DNS record: {e}",
            )

    async def get_records(self, zone_id: str) -> list[DNSRRSetDTO]:
        """Retrieve all DNS records for the specified zone."""
        response = await self._client_authoritative.get(
            f"/zones/{zone_id}",
        )

        await self._validate_response(response)
        zone = base_retort.load(response.json(), DNSZoneMasterDTO)

        return zone.rrsets

    async def update_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Update a DNS record in the specified zone."""
        if not record.name.endswith("."):
            record.name += "."

        record.changetype = PowerDNSRecordChangeType.REPLACE

        response = await self._client_authoritative.patch(
            f"/zones/{zone_id}",
            json={"rrsets": [base_retort.dump(record)]},
        )

        try:
            await self._validate_response(response)
        except httpx.HTTPError as e:
            raise DNSRecordUpdateError(
                f"Failed to update DNS record: {e}",
            )

    async def delete_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Delete a DNS record from the specified zone."""
        if not record.name.endswith("."):
            record.name += "."

        record.changetype = PowerDNSRecordChangeType.DELETE

        response = await self._client_authoritative.patch(
            f"/zones/{zone_id}",
            json={"rrsets": [base_retort.dump(record)]},
        )

        try:
            await self._validate_response(response)
        except httpx.HTTPError as e:
            raise DNSRecordDeleteError(
                f"Failed to delete DNS record: {e}",
            )

    async def create_zone(self, zone: DNSZoneBaseDTO) -> None:
        """Create a DNS zone."""
        if not zone.name.endswith("."):
            zone.name += "."

        if isinstance(zone, DNSZoneForwardDTO):
            client = self._client_recursor
        elif isinstance(zone, DNSZoneMasterDTO):
            client = self._client_authoritative
            zone.nameservers.append(f"ns1.{zone.name}")

            records = await get_new_zone_records(
                zone.name,
                str(self._dns_settings.dns_server_ip),
            )

            zone.rrsets.extend(records)

        response = await client.post(
            "/zones",
            json=base_retort.dump(zone),
        )

        try:
            await self._validate_response(response)
        except httpx.HTTPError as e:
            raise DNSZoneCreateError(
                f"Failed to create DNS zone: {e}",
            )

    async def get_zones(self) -> list[DNSZoneMasterDTO]:
        """Retrieve all DNS zones."""
        response = await self._client_authoritative.get(
            "/zones",
        )
        await self._validate_response(response)

        zones = base_retort.load(response.json(), list[DNSZoneMasterDTO])
        for zone in zones:
            zone.rrsets = await self.get_records(zone.id)

        return zones

    async def get_forward_zones(self) -> list[DNSZoneForwardDTO]:
        """Retrieve all forward DNS zones."""
        response = await self._client_recursor.get(
            "/zones",
        )
        await self._validate_response(response)

        zones = base_retort.load(response.json(), list[DNSZoneForwardDTO])

        filtered_zones = []
        for zone in zones:
            if zone.kind == "Native":
                continue
            filtered_zones.append(zone)

        return filtered_zones

    async def update_zone(self, zone: DNSZoneBaseDTO) -> None:
        """Update a DNS zone."""
        if isinstance(zone, DNSZoneForwardDTO):
            client = self._client_recursor
        elif isinstance(zone, DNSZoneMasterDTO):
            client = self._client_authoritative

        response = await client.put(
            f"/zones/{zone.id}",
            json=base_retort.dump(zone),
        )

        try:
            await self._validate_response(response)
        except httpx.HTTPError as e:
            raise DNSZoneUpdateError(
                f"Failed to update DNS zone: {e}",
            )

    async def delete_zone(self, zone_id: str) -> None:
        """Delete a DNS zone."""
        response = await self._client_authoritative.delete(
            f"/zones/{zone_id}",
        )

        try:
            await self._validate_response(response)
        except httpx.HTTPError as e:
            raise DNSZoneDeleteError(
                f"Failed to delete DNS zone: {e}",
            )

    async def delete_forward_zone(self, zone_id: str) -> None:
        """Delete a DNS forward zone."""
        response = await self._client_recursor.delete(
            f"/zones/{zone_id}",
        )

        try:
            await self._validate_response(response)
        except httpx.HTTPError as e:
            raise DNSZoneDeleteError(
                f"Failed to delete DNS zone: {e}",
            )

    async def find_forward_dns_fqdn(
        self,
        dns_server_ip: IPv4Address | IPv6Address,
        host_dns_servers: list[str],
    ) -> str | None:
        """Find forward DNS FQDN."""
        reversed_ip = (
            ".".join(reversed((str(dns_server_ip)).split(".")))
            + ".in-addr.arpa"
        )

        async def get_fqdn_and_latency(
            server: str,
        ) -> tuple[float, str | None]:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = [server]
            resolver.timeout = 10

            try:
                event_loop = asyncio.get_running_loop()
                start_time = event_loop.time()
                fqdn = await resolver.resolve(
                    reversed_ip,
                    "PTR",
                )
                latency = event_loop.time() - start_time

                return (latency, fqdn[0].to_text())
            except (
                dns.asyncresolver.NoAnswer,
                dns.asyncresolver.NXDOMAIN,
            ):
                return (float("inf"), None)

        fqdn_list = await asyncio.gather(
            *(get_fqdn_and_latency(server) for server in host_dns_servers),
        )
        fqdn_list.sort(key=lambda x: x[0])
        return fqdn_list[0][1] if fqdn_list else None

    async def check_forward_dns_server(
        self,
        dns_server_ip: IPv4Address | IPv6Address,
        host_dns_servers: list[str],
    ) -> DNSForwardServerStatus:
        str_dns_server_ip = str(dns_server_ip)

        try:
            fqdn = await self.find_forward_dns_fqdn(
                dns_server_ip,
                host_dns_servers,
            )
        except (dns.asyncresolver.NoAnswer, dns.asyncresolver.NXDOMAIN):
            return DNSForwardServerStatus(
                str_dns_server_ip,
                DNSForwarderServerStatus.NOT_VALIDATED,
                None,
            )

        if not fqdn:
            return DNSForwardServerStatus(
                str_dns_server_ip,
                DNSForwarderServerStatus.NOT_FOUND,
                None,
            )

        return DNSForwardServerStatus(
            str_dns_server_ip,
            DNSForwarderServerStatus.VALIDATED,
            fqdn,
        )
