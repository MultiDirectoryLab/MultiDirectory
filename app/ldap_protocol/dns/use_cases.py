"""DNS use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import ClassVar

from abstract_service import AbstractService
from config import Settings
from enums import AuthorizationRules
from ldap_protocol.dns.base import (
    AbstractDNSManager,
    DNSForwardServerStatus,
    DNSForwardZone,
    DNSManagerSettings,
    DNSRecords,
    DNSServerParam,
    DNSZone,
    DNSZoneParam,
    DNSZoneType,
)
from ldap_protocol.dns.dns_gateway import DNSStateGateway


class DNSUseCase(AbstractService):
    """DNS use case."""

    def __init__(
        self,
        dns_manager: AbstractDNSManager,
        dns_gateway: DNSStateGateway,
        dns_settings: DNSManagerSettings,
        settings: Settings,
    ) -> None:
        """Initialize DNS use case."""
        self._dns_manager = dns_manager
        self._settings = settings
        self._dns_settings = dns_settings
        self._dns_gateway = dns_gateway

    async def setup_dns(
        self,
        dns_status: str,
        domain: str,
        dns_ip_address: str | IPv4Address | IPv6Address | None,
        tsig_key: str | None,
    ) -> None:
        """Set up DNS server and DNS manager."""
        setup_data = await self._dns_manager.setup(
            dns_status,
            domain,
            dns_ip_address or self._settings.DNS_BIND_HOST,
            tsig_key,
        )
        if self._dns_settings.domain is not None:
            await self._dns_gateway.update_settings(setup_data)
        else:
            await self._dns_gateway.create_settings(setup_data)

        await self._dns_gateway.setup_dns_state(dns_status)

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
            "dns_status": await self._dns_gateway.get_dns_state(),
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

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {
        setup_dns.__name__: AuthorizationRules.DNS_SETUP_DNS,
        create_record.__name__: AuthorizationRules.DNS_CREATE_RECORD,
        delete_record.__name__: AuthorizationRules.DNS_DELETE_RECORD,
        update_record.__name__: AuthorizationRules.DNS_UPDATE_RECORD,
        get_all_records.__name__: AuthorizationRules.DNS_GET_ALL_RECORDS,
        get_dns_status.__name__: AuthorizationRules.DNS_GET_DNS_STATUS,
        get_all_zones_records.__name__: AuthorizationRules.DNS_GET_ALL_ZONES_RECORDS,  # noqa: E501
        get_forward_zones.__name__: AuthorizationRules.DNS_GET_FORWARD_ZONES,
        create_zone.__name__: AuthorizationRules.DNS_CREATE_ZONE,
        update_zone.__name__: AuthorizationRules.DNS_UPDATE_ZONE,
        delete_zone.__name__: AuthorizationRules.DNS_DELETE_ZONE,
        check_dns_forward_zone.__name__: AuthorizationRules.DNS_CHECK_DNS_FORWARD_ZONE,  # noqa: E501
        reload_zone.__name__: AuthorizationRules.DNS_RELOAD_ZONE,
        update_server_options.__name__: AuthorizationRules.DNS_UPDATE_SERVER_OPTIONS,  # noqa: E501
        get_server_options.__name__: AuthorizationRules.DNS_GET_SERVER_OPTIONS,
        restart_server.__name__: AuthorizationRules.DNS_RESTART_SERVER,
    }
