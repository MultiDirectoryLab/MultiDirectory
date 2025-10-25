"""DNS use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from dns.asyncresolver import Resolver as AsyncResolver
from sqlalchemy.ext.asyncio import AsyncSession

from abstract_dao import AbstractService
from config import Settings
from entities import CatalogueSetting
from ldap_protocol.dns.base import (
    DNS_MANAGER_IP_ADDRESS_NAME,
    DNS_MANAGER_STATE_NAME,
    DNS_MANAGER_TSIG_KEY_NAME,
    DNS_MANAGER_ZONE_NAME,
    AbstractDNSManager,
    DNSConnectionError,
    DNSForwardServerStatus,
    DNSForwardZone,
    DNSManagerSettings,
    DNSManagerState,
    DNSRecords,
    DNSServerParam,
    DNSZone,
    DNSZoneParam,
    DNSZoneType,
)
from ldap_protocol.dns.dns_gateway import DNSGateway


class DNSUseCase(AbstractService):
    """DNS use case."""

    def __init__(
        self,
        dns_manager: AbstractDNSManager,
        dns_gateway: DNSGateway,
        dns_settings: DNSManagerSettings,
        settings: Settings,
        session: AsyncSession,
    ) -> None:
        """Initialize DNS use case."""
        self._dns_manager = dns_manager
        self._settings = settings
        self._dns_settings = dns_settings
        self._session = session
        self._dns_gateway = dns_gateway

    async def setup_dns(
        self,
        dns_status: str,
        domain: str,
        dns_ip_address: str | IPv4Address | IPv6Address | None,
        tsig_key: str | None,
    ) -> None:
        """Set up DNS server and DNS manager."""
        await self._dns_manager.setup(
            self._session,
            dns_status,
            domain,
            dns_ip_address or self._settings.DNS_BIND_HOST,
            tsig_key,
        )
        await self._dns_gateway.setup_dns(dns_status)

    async def get_dns_state(self) -> DNSManagerState:
        """Get DNS state."""
        state = await self._dns_gateway.get_by_name(DNS_MANAGER_STATE_NAME)
        if state is None:
            await self._dns_gateway.create(
                CatalogueSetting(
                    name=DNS_MANAGER_STATE_NAME,
                    value=DNSManagerState.NOT_CONFIGURED,
                ),
            )
            return DNSManagerState.NOT_CONFIGURED
        return DNSManagerState(state.value)

    async def resolve_dns_server_ip(self, host: str) -> str:
        """Resolve DNS server IP."""
        async_resolver = AsyncResolver()
        dns_server_ip_resolve = await async_resolver.resolve(host)
        if (
            dns_server_ip_resolve is None
            or dns_server_ip_resolve.rrset is None
        ):
            raise DNSConnectionError
        return dns_server_ip_resolve.rrset[0].address

    async def get_dns_manager_settings(self) -> DNSManagerSettings:
        """Get DNS manager settings."""
        settings = {
            setting.name: setting.value
            for setting in await self._dns_gateway.get_dns_managers()
        }
        dns_server_ip = settings.get(DNS_MANAGER_IP_ADDRESS_NAME)

        if await self.get_dns_state() == DNSManagerState.SELFHOSTED:
            dns_server_ip = await self.resolve_dns_server_ip(
                self._settings.DNS_BIND_HOST,
            )

        return DNSManagerSettings(
            zone_name=settings.get(DNS_MANAGER_ZONE_NAME),
            dns_server_ip=dns_server_ip,
            tsig_key=settings.get(DNS_MANAGER_TSIG_KEY_NAME),
        )

    async def create_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None:
        """Create DNS record."""
        await self._dns_manager.create_record(
            hostname,
            ip,
            record_type,
            ttl,
            zone_name,
        )

    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        zone_name: str | None = None,
    ) -> None:
        """Delete DNS record."""
        await self._dns_manager.delete_record(
            hostname,
            ip,
            record_type,
            zone_name,
        )

    async def update_record(
        self,
        hostname: str,
        ip: str | None,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None:
        """Update DNS record."""
        await self._dns_manager.update_record(
            hostname,
            ip,
            record_type,
            ttl,
            zone_name,
        )

    async def get_all_records(self) -> list[DNSRecords]:
        """Get all DNS records."""
        return await self._dns_manager.get_all_records()

    async def get_all_zones_records(self) -> list[DNSZone]:
        """Get all DNS zones."""
        return await self._dns_manager.get_all_zones_records()

    async def get_forward_zones(self) -> list[DNSForwardZone]:
        """Get all forward zones."""
        return await self._dns_manager.get_forward_zones()

    async def create_zone(
        self,
        zone_name: str,
        zone_type: DNSZoneType,
        nameserver: str | None,
        params: list[DNSZoneParam],
    ) -> None:
        """Create DNS zone."""
        await self._dns_manager.create_zone(
            zone_name,
            zone_type,
            nameserver,
            params,
        )

    async def update_zone(
        self,
        zone_name: str,
        params: list[DNSZoneParam] | None,
    ) -> None:
        """Update DNS zone."""
        await self._dns_manager.update_zone(zone_name, params)

    async def delete_zone(self, zone_names: list[str]) -> None:
        """Delete DNS zone."""
        await self._dns_manager.delete_zone(zone_names)

    async def check_forward_dns_server(
        self,
        dns_server_ip: IPv4Address | IPv6Address,
        host_dns_servers: list[str],
    ) -> DNSForwardServerStatus:
        """Check DNS forward server."""
        return await self._dns_manager.check_forward_dns_server(
            dns_server_ip,
            host_dns_servers,
        )

    async def check_forward_dns_zone(
        self,
        data: list[IPv4Address | IPv6Address],
    ) -> list[DNSForwardServerStatus]:
        """Check DNS forward zone for availability."""
        return [
            await self.check_forward_dns_server(
                dns_server_ip,
                self._settings.HOST_DNS_SERVERS,
            )
            for dns_server_ip in data
        ]

    async def update_server_options(
        self,
        params: list[DNSServerParam],
    ) -> None:
        """Update DNS server options."""
        await self._dns_manager.update_server_options(params)

    async def restart_server(self) -> None:
        """Restart DNS server."""
        await self._dns_manager.restart_server()

    async def reload_zone(self, zone_name: str) -> None:
        """Reload DNS zone."""
        await self._dns_manager.reload_zone(zone_name)

    async def get_server_options(self) -> list[DNSServerParam]:
        """Get DNS server options."""
        return await self._dns_manager.get_server_options()

    async def get_dns_status(self) -> dict[str, str | None]:
        """Get DNS status."""
        return {
            "dns_status": await self.get_dns_state(),
            "zone_name": self._dns_settings.zone_name,
            "dns_server_ip": self._dns_settings.dns_server_ip,
        }

    async def check_dns_forward_zone(
        self,
        data: list[IPv4Address | IPv6Address],
    ) -> list[DNSForwardServerStatus]:
        """Check DNS forward zone for availability."""
        return [
            await self.check_forward_dns_server(
                dns_server_ip,
                self._settings.HOST_DNS_SERVERS,
            )
            for dns_server_ip in data
        ]
