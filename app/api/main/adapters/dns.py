"""DNS adapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from api.base_adapter import BaseAdapter
from api.main.schema import (
    DNSServiceForwardZoneCheckRequest,
    DNSServiceForwardZoneRequest,
    DNSServiceMasterZoneRequest,
    DNSServiceRecordCreateRequest,
    DNSServiceRecordDeleteRequest,
    DNSServiceRecordUpdateRequest,
    DNSServiceSetStateRequest,
    DNSServiceSetupRequest,
    DNSServiceZoneDeleteRequest,
)
from ldap_protocol.dns.base import DNSForwardServerStatus
from ldap_protocol.dns.dto import (
    DNSRecordDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
    DNSZoneForwardDTO,
    DNSZoneMasterDTO,
)
from ldap_protocol.dns.enums import DNSRecordType, PowerDNSRecordChangeType
from ldap_protocol.dns.use_cases import DNSUseCase


class DNSFastAPIAdapter(BaseAdapter[DNSUseCase]):
    """DNS adapter."""

    async def create_record(
        self,
        zone_id: str,
        data: DNSServiceRecordCreateRequest,
    ) -> None:
        """Create DNS record."""
        await self._service.create_record(
            zone_id,
            DNSRRSetDTO(
                name=data.record_name,
                type=DNSRecordType(data.record_type),
                records=[
                    DNSRecordDTO(
                        content=data.record_value,
                        disabled=False,
                    ),
                ],
                ttl=data.ttl,
            ),
        )

    async def delete_record(
        self,
        zone_id: str,
        data: DNSServiceRecordDeleteRequest,
    ) -> None:
        """Delete DNS record."""
        await self._service.delete_record(
            zone_id,
            DNSRRSetDTO(
                name=data.record_name,
                type=data.record_type,
                records=[
                    DNSRecordDTO(
                        content=data.record_value,
                        disabled=False,
                    ),
                ],
            ),
        )

    async def update_record(
        self,
        zone_id: str,
        data: DNSServiceRecordUpdateRequest,
    ) -> None:
        """Update DNS record."""
        await self._service.update_record(
            zone_id,
            DNSRRSetDTO(
                name=data.record_name,
                type=data.record_type,
                records=[
                    DNSRecordDTO(
                        content=data.record_value,
                        disabled=False,
                    ),
                ],
                changetype=PowerDNSRecordChangeType.REPLACE,
                ttl=data.ttl,
            ),
        )

    async def get_records(self, zone_id: str) -> list[DNSRRSetDTO]:
        """Get all DNS records of current zone."""
        return await self._service.get_records(zone_id)

    async def get_dns_status(self) -> dict[str, str | None]:
        """Get DNS service status."""
        return await self._service.get_dns_status()

    async def set_dns_state(
        self,
        data: DNSServiceSetStateRequest,
    ) -> None:
        """Set DNS manager state."""
        await self._service.set_state(data.state)

    async def setup_dns(self, data: DNSServiceSetupRequest) -> None:
        await self._service.setup_dns(
            DNSSettingsDTO(
                dns_server_ip=data.dns_ip_address,
                tsig_key=data.tsig_key,
                domain=data.domain,
            ),
        )

    async def create_forward_zone(
        self,
        data: DNSServiceForwardZoneRequest,
    ) -> None:
        """Create new DNS forward zone."""
        await self._service.create_zone(
            DNSZoneForwardDTO(
                id=data.zone_name,
                name=data.zone_name,
                servers=data.servers,
            ),
        )

    async def get_forward_dns_zones(self) -> list[DNSZoneForwardDTO]:
        """Get list of DNS forward zones with forwarders."""
        return await self._service.get_forward_zones()

    async def update_forward_zone(
        self,
        data: DNSServiceForwardZoneRequest,
    ) -> None:
        """Update DNS forward zone with given params."""
        await self._service.update_zone(
            DNSZoneForwardDTO(
                id=data.zone_name,
                name=data.zone_name,
                servers=data.servers,
            ),
        )

    async def delete_forward_zones(
        self,
        data: DNSServiceZoneDeleteRequest,
    ) -> None:
        """Delete DNS forward zones."""
        await self._service.delete_forward_zones(data.zone_ids)

    async def create_zone(
        self,
        data: DNSServiceMasterZoneRequest,
    ) -> None:
        """Create new DNS zone."""
        await self._service.create_zone(
            DNSZoneMasterDTO(
                id=data.zone_name,
                name=data.zone_name,
                dnssec=data.dnssec,
            ),
        )

    async def get_dns_zone(self) -> list[DNSZoneMasterDTO]:
        """Get all DNS zones."""
        return await self._service.get_zones()

    async def update_zone(self, data: DNSServiceMasterZoneRequest) -> None:
        """Update DNS zone with given params."""
        await self._service.update_zone(
            DNSZoneMasterDTO(
                id=data.zone_name,
                name=data.zone_name,
                dnssec=False,
            ),
        )

    async def delete_zones(self, data: DNSServiceZoneDeleteRequest) -> None:
        """Delete DNS zones."""
        await self._service.delete_zones(data.zone_ids)

    async def check_dns_forward_zone(
        self,
        data: DNSServiceForwardZoneCheckRequest,
    ) -> list[DNSForwardServerStatus]:
        """Check DNS forward zone for availability."""
        return await self._service.check_dns_forward_zone(data.dns_server_ips)
