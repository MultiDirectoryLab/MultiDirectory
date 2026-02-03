"""PowerDNS API manager module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from ipaddress import IPv4Address, IPv6Address

import dns.asyncresolver

from ldap_protocol.dns.clients import (
    PowerDNSAuthHTTPClient,
    PowerDNSDistClient,
    PowerDNSRecursorHTTPClient,
)
from ldap_protocol.dns.constants import DNS_FIRST_SETUP_RECORDS
from ldap_protocol.dns.dto import (
    DNSForwardServerStatus,
    DNSForwardZoneDTO,
    DNSMasterZoneDTO,
    DNSRecordDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
)
from ldap_protocol.dns.enums import (
    DNSForwarderServerStatus,
    DNSRecordType,
    PowerDNSRecordChangeType,
)
from ldap_protocol.dns.exceptions import (
    DNSError,
    DNSRecordCreateError,
    DNSRecordDeleteError,
    DNSRecordGetError,
    DNSRecordUpdateError,
    DNSSetupError,
    DNSZoneCreateError,
    DNSZoneDeleteError,
    DNSZoneGetError,
    DNSZoneUpdateError,
)
from ldap_protocol.dns.managers.abstract_dns_manager import AbstractDNSManager
from ldap_protocol.dns.utils import create_initial_zone_records


class PowerDNSManager(AbstractDNSManager):
    """Manager for interacting with the PowerDNS API."""

    _power_dns_auth_client: PowerDNSAuthHTTPClient
    _power_dns_recursor_client: PowerDNSRecursorHTTPClient
    _dnsdist_client: PowerDNSDistClient

    def __init__(
        self,
        settings: DNSSettingsDTO,
        power_dns_auth_client: PowerDNSAuthHTTPClient,
        power_dns_recursor_client: PowerDNSRecursorHTTPClient,
        dnsdist_client: PowerDNSDistClient,
    ) -> None:
        """Initialize the PowerDNS API repository."""
        super().__init__(settings)
        self._power_dns_auth_client = power_dns_auth_client
        self._power_dns_recursor_client = power_dns_recursor_client
        self._dnsdist_client = dnsdist_client

    @staticmethod
    def _normalize_dns_name(name: str) -> str:
        """Normalize DNS name by ensuring it ends with a dot."""
        return name if name.endswith(".") else f"{name}."

    async def setup(self, dns_settings: DNSSettingsDTO) -> None:
        """Set up DNS server and DNS manager."""
        records = []
        if dns_settings.power_dns_settings is None:
            raise DNSError("PowerDNS settings is not set.")

        for record in DNS_FIRST_SETUP_RECORDS:
            records.append(
                DNSRRSetDTO(
                    name=f"{record['name']}{self._dns_settings.domain}.",
                    type=DNSRecordType(record["type"]),
                    records=[
                        DNSRecordDTO(
                            content=f"{record['value']}{self._dns_settings.domain}.",
                            disabled=False,
                            modified_at=None,
                        ),
                    ],
                    changetype=PowerDNSRecordChangeType.EXTEND,
                    ttl=3600,
                ),
            )

        try:
            await self.create_master_zone(
                DNSMasterZoneDTO(
                    id=self._dns_settings.domain,
                    name=self._dns_settings.domain,
                    dnssec=False,
                    rrsets=records,
                ),
            )
            self._dnsdist_client.setup_dnsdist(
                dns_settings.power_dns_settings.recursor_server_ip,
            )
            self._dnsdist_client.add_server(
                dns_settings.power_dns_settings.auth_server_ip,
                "master",
            )
        except DNSZoneCreateError as e:
            raise DNSSetupError(f"Failed to set up DNS: {e}")

    async def create_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Create a DNS record in the specified zone."""
        record.name = self._normalize_dns_name(record.name)

        record.changetype = PowerDNSRecordChangeType.REPLACE

        try:
            await self._power_dns_auth_client.create_record(zone_id, record)
        except DNSError as e:
            raise DNSRecordCreateError(f"Failed to create DNS record: {e}")

    async def get_records(self, zone_id: str) -> list[DNSRRSetDTO]:
        """Retrieve all DNS records for the specified zone."""
        try:
            return await self._power_dns_auth_client.get_records(zone_id)
        except DNSError as e:
            raise DNSRecordGetError(f"Failed to get DNS records: {e}")

    async def update_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Update a DNS record in the specified zone."""
        record.name = self._normalize_dns_name(record.name)

        record.changetype = PowerDNSRecordChangeType.REPLACE

        try:
            await self._power_dns_auth_client.update_record(zone_id, record)
        except DNSError as e:
            raise DNSRecordUpdateError(f"Failed to update DNS record: {e}")

    async def delete_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Delete a DNS record from the specified zone."""
        record.name = self._normalize_dns_name(record.name)

        record.changetype = PowerDNSRecordChangeType.DELETE

        try:
            await self._power_dns_auth_client.delete_record(zone_id, record)
        except DNSError as e:
            raise DNSRecordDeleteError(f"Failed to delete DNS record: {e}")

    async def create_master_zone(self, zone: DNSMasterZoneDTO) -> None:
        """Create a master DNS zone."""
        zone.name = self._normalize_dns_name(zone.name)

        zone.nameservers.append(f"ns1.{zone.name}")

        records = await create_initial_zone_records(
            zone.name,
            self._dns_settings.default_nameserver,
        )
        zone.rrsets.extend(records)

        try:
            await self._power_dns_auth_client.create_master_zone(zone)
            self._dnsdist_client.add_zone_rule(
                zone.name if not zone.name.endswith(".") else zone.name[:-1],
            )
        except DNSError as e:
            raise DNSZoneCreateError(f"Failed to create DNS zone: {e}")

    async def create_forward_zone(self, zone: DNSForwardZoneDTO) -> None:
        """Create a forward DNS zone."""
        zone.name = self._normalize_dns_name(zone.name)

        try:
            await self._power_dns_recursor_client.create_forward_zone(zone)
        except DNSError as e:
            raise DNSZoneCreateError(f"Failed to create DNS zone: {e}")

    async def get_master_zones(self) -> list[DNSMasterZoneDTO]:
        """Retrieve all DNS zones."""
        try:
            zones = await self._power_dns_auth_client.get_master_zones()
        except DNSError as e:
            raise DNSZoneGetError(f"Failed to get DNS zones: {e}")

        for zone in zones:
            zone.rrsets = await self.get_records(zone.id)

        return zones

    async def get_master_zone_by_id(self, zone_id: str) -> DNSMasterZoneDTO:
        """Get master DNS zone by ID."""
        try:
            return await self._power_dns_auth_client.get_master_zone_by_id(
                zone_id,
            )
        except DNSError as e:
            raise DNSZoneGetError(f"Failed to get DNS zones: {e}")

    async def get_forward_zones(self) -> list[DNSForwardZoneDTO]:
        """Retrieve all forward DNS zones."""
        try:
            return await self._power_dns_recursor_client.get_forward_zones()
        except DNSError as e:
            raise DNSZoneGetError(f"Failed to get DNS zones: {e}")

    async def update_master_zone(self, zone: DNSMasterZoneDTO) -> None:
        """Update a master DNS zone."""
        zone.name = self._normalize_dns_name(zone.name)
        try:
            await self._power_dns_auth_client.update_master_zone(zone.id, zone)
        except DNSError as e:
            raise DNSZoneUpdateError(f"Failed to update DNS zone: {e}")

    async def update_forward_zone(self, zone: DNSForwardZoneDTO) -> None:
        """Update a forward DNS zone."""
        zone.name = self._normalize_dns_name(zone.name)

        try:
            await self._power_dns_recursor_client.update_forward_zone(
                zone.id,
                zone,
            )
        except DNSError as e:
            raise DNSZoneUpdateError(f"Failed to update DNS zone: {e}")

    async def delete_master_zone(self, zone_id: str) -> None:
        """Delete a DNS zone."""
        zone = await self.get_master_zone_by_id(zone_id)

        try:
            await self._power_dns_auth_client.delete_master_zone(zone_id)
            self._dnsdist_client.remove_zone_rule(zone.name)
        except DNSError as e:
            raise DNSZoneDeleteError(f"Failed to delete DNS zone: {e}")

    async def delete_forward_zone(self, zone_id: str) -> None:
        """Delete a DNS forward zone."""
        try:
            await self._power_dns_recursor_client.delete_forward_zone(zone_id)
        except DNSError as e:
            raise DNSZoneDeleteError(f"Failed to delete DNS zone: {e}")

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
                fqdn = await resolver.resolve(reversed_ip, DNSRecordType.PTR)
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
