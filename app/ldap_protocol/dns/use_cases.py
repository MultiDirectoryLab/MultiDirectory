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
    DNSManagerSettings,
)
from ldap_protocol.dns.dns_gateway import DNSStateGateway
from ldap_protocol.dns.dto import (
    DNSForwardZoneDTO,
    DNSMasterZoneDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
    DNSZoneBaseDTO,
)

from .enums import DNSManagerState


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
        dns_server_settings: DNSSettingsDTO,
    ) -> None:
        """Set up DNS server and DNS manager."""
        await self._dns_manager.setup(
            dns_server_settings,
        )
        if self._dns_settings.domain is not None:
            await self._dns_gateway.update_settings(dns_server_settings)
        else:
            await self._dns_gateway.create_settings(dns_server_settings)

    async def create_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None:
        """Create DNS record."""
        await self._dns_manager.create_record(
            zone_id,
            record,
        )

    async def get_records(self, zone_id: str) -> list[DNSRRSetDTO]:
        """Get all DNS records."""
        return await self._dns_manager.get_records(zone_id)

    async def update_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None:
        """Update DNS record."""
        await self._dns_manager.update_record(
            zone_id,
            record,
        )

    async def delete_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None:
        """Delete DNS record."""
        await self._dns_manager.delete_record(
            zone_id,
            record,
        )

    async def create_zone(
        self,
        zone: DNSZoneBaseDTO,
    ) -> None:
        """Create DNS zone."""
        await self._dns_manager.create_zone(zone)

    async def get_zones(self) -> list[DNSMasterZoneDTO]:
        """Get all DNS zones."""
        return await self._dns_manager.get_zones()

    async def get_forward_zones(self) -> list[DNSForwardZoneDTO]:
        """Get all forward zones."""
        return await self._dns_manager.get_forward_zones()

    async def update_zone(
        self,
        zone: DNSZoneBaseDTO,
    ) -> None:
        """Update DNS zone."""
        await self._dns_manager.update_zone(zone)

    async def delete_zones(self, zone_ids: list[str]) -> None:
        """Delete DNS zones."""
        for zone_id in zone_ids:
            await self._dns_manager.delete_zone(zone_id)

    async def delete_forward_zones(self, zone_ids: list[str]) -> None:
        """Delete DNS forward zones."""
        for zone_id in zone_ids:
            await self._dns_manager.delete_forward_zone(zone_id)

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

    async def get_dns_status(self) -> dict[str, str | None]:
        """Get DNS status."""
        return {
            "dns_status": await self._dns_gateway.get_dns_state(),
            "zone_name": self._dns_settings.domain,
            "dns_server_ip": str(self._dns_settings.dns_server_ip),
        }

    async def set_state(
        self,
        state: DNSManagerState,
    ) -> None:
        """Set DNS manager state."""
        await self._dns_gateway.set_state(state)

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
        get_records.__name__: AuthorizationRules.DNS_GET_ALL_RECORDS,
        get_dns_status.__name__: AuthorizationRules.DNS_GET_DNS_STATUS,
        delete_forward_zones.__name__: AuthorizationRules.DNS_DELETE_FWD_ZONES,
        get_forward_zones.__name__: AuthorizationRules.DNS_GET_FORWARD_ZONES,
        create_zone.__name__: AuthorizationRules.DNS_CREATE_ZONE,
        update_zone.__name__: AuthorizationRules.DNS_UPDATE_ZONE,
        delete_zones.__name__: AuthorizationRules.DNS_DELETE_ZONE,
        check_dns_forward_zone.__name__: AuthorizationRules.DNS_CHECK_DNS_FORWARD_ZONE,  # noqa: E501
    }
