"""DNS use cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import ClassVar

from abstract_service import AbstractService
from config import Settings
from enums import AuthorizationRules
from ldap_protocol.dns.dns_gateway import DNSStateGateway
from ldap_protocol.dns.dto import (
    DNSForwardServerStatus,
    DNSForwardZoneDTO,
    DNSMasterZoneDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
)
from ldap_protocol.dns.enums import DNSManagerState
from ldap_protocol.dns.exceptions import DNSError, DNSSetupError
from ldap_protocol.dns.managers.abstract_dns_manager import AbstractDNSManager


class DNSUseCase(AbstractService):
    """DNS use case."""

    def __init__(
        self,
        dns_manager: AbstractDNSManager,
        dns_gateway: DNSStateGateway,
        dns_settings: DNSSettingsDTO,
        settings: Settings,
    ) -> None:
        """Initialize DNS use case."""
        self._dns_manager = dns_manager
        self._settings = settings
        self._dns_settings = dns_settings
        self._dns_gateway = dns_gateway

    async def setup(
        self,
        dns_settings: DNSSettingsDTO | None,
    ) -> None:
        """Set up DNS server and DNS manager."""
        state = await self._dns_gateway.get_state()

        if state == DNSManagerState.SELFHOSTED:
            await self._dns_manager.setup(
                self._dns_settings,
            )
        elif state == DNSManagerState.HOSTED:
            if dns_settings is None:
                raise DNSSetupError()
            if self._dns_settings.dns_server_ip is None:
                await self._dns_gateway.create_settings(dns_settings)
            else:
                await self._dns_gateway.update_settings(dns_settings)
        else:
            raise DNSSetupError()

    async def create_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None:
        """Create DNS record."""
        await self._dns_manager.create_record(zone_id, record)

    async def get_records(self, zone_id: str) -> list[DNSRRSetDTO]:
        """Get all DNS records."""
        return await self._dns_manager.get_records(zone_id)

    async def update_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Update DNS record."""
        await self._dns_manager.update_record(zone_id, record)

    async def delete_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Delete DNS record."""
        await self._dns_manager.delete_record(zone_id, record)

    async def create_master_zone(self, zone: DNSMasterZoneDTO) -> None:
        """Create DNS master zone."""
        await self._dns_manager.create_master_zone(zone)

    async def create_forward_zone(self, zone: DNSForwardZoneDTO) -> None:
        """Create DNS forward zone."""
        await self._dns_manager.create_forward_zone(zone)

    async def get_master_zones(self) -> list[DNSMasterZoneDTO]:
        """Get all DNS zones."""
        return await self._dns_manager.get_master_zones()

    async def get_forward_zones(self) -> list[DNSForwardZoneDTO]:
        """Get all forward zones."""
        return await self._dns_manager.get_forward_zones()

    async def update_master_zone(self, zone: DNSMasterZoneDTO) -> None:
        """Update DNS master zone."""
        await self._dns_manager.update_master_zone(zone)

    async def update_forward_zone(self, zone: DNSForwardZoneDTO) -> None:
        """Update DNS forward zone."""
        await self._dns_manager.update_forward_zone(zone)

    async def delete_master_zones(self, zone_ids: list[str]) -> None:
        """Delete DNS master zones."""
        last_error = None
        try:
            for zone_id in zone_ids:
                await self._dns_manager.delete_master_zone(zone_id)
        except DNSError as e:
            last_error = e
        if last_error:
            raise last_error

    async def delete_forward_zones(self, zone_ids: list[str]) -> None:
        """Delete DNS forward zones."""
        last_error = None
        try:
            for zone_id in zone_ids:
                await self._dns_manager.delete_forward_zone(zone_id)
        except DNSError as e:
            last_error = e
        if last_error:
            raise last_error

    async def check_forward_server(
        self,
        dns_server_ip: IPv4Address | IPv6Address,
        host_dns_servers: list[str],
    ) -> DNSForwardServerStatus:
        """Check DNS forward server."""
        return await self._dns_manager.check_forward_dns_server(
            dns_server_ip,
            host_dns_servers,
        )

    async def get_status(self) -> dict[str, str | None]:
        """Get DNS status."""
        return {
            "dns_status": await self._dns_gateway.get_state(),
            "zone_name": self._dns_settings.domain,
            "dns_server_ip": str(self._dns_settings.dns_server_ip),
        }

    async def set_state(self, state: DNSManagerState) -> None:
        """Set DNS manager state."""
        await self._dns_gateway.set_state(state)

    async def check_forward_zone(
        self,
        data: list[IPv4Address | IPv6Address],
    ) -> list[DNSForwardServerStatus]:
        """Check DNS forward zone for availability."""
        return [
            await self.check_forward_server(
                dns_server_ip,
                self._settings.HOST_DNS_SERVERS,
            )
            for dns_server_ip in data
        ]

    PERMISSIONS: ClassVar[dict[str, AuthorizationRules]] = {
        setup.__name__: AuthorizationRules.DNS_SETUP_DNS,
        create_record.__name__: AuthorizationRules.DNS_CREATE_RECORD,
        delete_record.__name__: AuthorizationRules.DNS_DELETE_RECORD,
        update_record.__name__: AuthorizationRules.DNS_UPDATE_RECORD,
        get_records.__name__: AuthorizationRules.DNS_GET_ALL_RECORDS,
        get_status.__name__: AuthorizationRules.DNS_GET_DNS_STATUS,
        delete_forward_zones.__name__: AuthorizationRules.DNS_DELETE_FWD_ZONES,
        get_master_zones.__name__: AuthorizationRules.DNS_GET_MASTER_ZONES,
        get_forward_zones.__name__: AuthorizationRules.DNS_GET_FWD_ZONES,
        create_master_zone.__name__: AuthorizationRules.DNS_CREATE_MASTER_ZONE,
        create_forward_zone.__name__: AuthorizationRules.DNS_CREATE_FWD_ZONE,
        update_master_zone.__name__: AuthorizationRules.DNS_UPDATE_MASTER_ZONE,
        update_forward_zone.__name__: AuthorizationRules.DNS_UPDATE_FWD_ZONE,
        delete_master_zones.__name__: AuthorizationRules.DNS_DELETE_MASTER_ZONES,  # noqa: E501
        delete_forward_zones.__name__: AuthorizationRules.DNS_DELETE_FWD_ZONES,
        check_forward_zone.__name__: AuthorizationRules.DNS_CHECK_DNS_FORWARD_ZONE,  # noqa: E501
    }
