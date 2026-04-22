"""DNS adapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from api.base_adapter import BaseAdapter
from api.dns.schema import (
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
from ldap_protocol.dns.dto import (
    DNSForwardServerStatus,
    DNSForwardZoneDTO,
    DNSMasterZoneDTO,
    DNSRecordDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
)
from ldap_protocol.dns.enums import DNSRecordType
from ldap_protocol.dns.use_cases import DNSUseCase


class DNSFastAPIAdapter(BaseAdapter[DNSUseCase]):
    """DNS adapter."""

    async def create_record(self, zone_id: str, data: DNSServiceRecordCreateRequest) -> None:
        """Create DNS record."""
        await self._service.create_record(
            zone_id,
            DNSRRSetDTO(
                name=data.record_name,
                type=DNSRecordType(data.record_type),
                records=[DNSRecordDTO(content=data.record_value, disabled=False)],
                ttl=data.ttl,
            ),
        )

    async def delete_record(self, zone_id: str, data: DNSServiceRecordDeleteRequest) -> None:
        """Delete DNS record."""
        await self._service.delete_record(
            zone_id,
            DNSRRSetDTO(
                name=data.record_name,
                type=data.record_type,
                records=[DNSRecordDTO(content=data.record_value, disabled=False)],
            ),
        )

    async def update_record(self, zone_id: str, data: DNSServiceRecordUpdateRequest) -> None:
        """Update DNS record."""
        await self._service.update_record(
            zone_id,
            DNSRRSetDTO(
                name=data.record_name,
                type=data.record_type,
                records=[DNSRecordDTO(content=data.record_value, disabled=False)],
                ttl=data.ttl,
            ),
        )

    async def get_records(self, zone_id: str) -> list[DNSRRSetDTO]:
        """Get all DNS records of current zone."""
        return await self._service.get_records(zone_id)

    async def get_status(self) -> dict[str, str | None]:
        """Get DNS service status."""
        return await self._service.get_status()

    async def set_state(self, data: DNSServiceSetStateRequest) -> None:
        """Set DNS manager state."""
        await self._service.set_state(data.state)

    async def setup(self, data: DNSServiceSetupRequest | None) -> None:
        await self._service.setup(
            DNSSettingsDTO(
                dns_server_ip=data.dns_ip_address,
                tsig_key=data.tsig_key,
                domain=data.domain,
                default_nameserver=str(data.dns_ip_address),
            )
            if data is not None
            else data
        )

    async def create_forward_zone(self, data: DNSServiceForwardZoneRequest) -> None:
        """Create new DNS forward zone."""
        await self._service.create_forward_zone(
            DNSForwardZoneDTO(id=data.zone_name, name=data.zone_name, servers=data.servers)
        )

    async def get_forward_zones(self) -> list[DNSForwardZoneDTO]:
        """Get list of DNS forward zones with forwarders."""
        return await self._service.get_forward_zones()

    async def update_forward_zone(self, data: DNSServiceForwardZoneRequest) -> None:
        """Update DNS forward zone with given params."""
        await self._service.update_forward_zone(
            DNSForwardZoneDTO(id=data.zone_name, name=data.zone_name, servers=data.servers)
        )

    async def delete_forward_zones(self, data: DNSServiceZoneDeleteRequest) -> None:
        """Delete DNS forward zones."""
        await self._service.delete_forward_zones(data.zone_ids)

    async def create_master_zone(self, data: DNSServiceMasterZoneRequest) -> None:
        """Create new DNS zone."""
        await self._service.create_master_zone(
            DNSMasterZoneDTO(id=data.zone_name, name=data.zone_name, dnssec=data.dnssec)
        )

    async def get_master_zones(self) -> list[DNSMasterZoneDTO]:
        """Get all DNS master zones."""
        return await self._service.get_master_zones()

    async def update_master_zone(self, data: DNSServiceMasterZoneRequest) -> None:
        """Update DNS zone with given params."""
        await self._service.update_master_zone(
            DNSMasterZoneDTO(id=data.zone_name, name=data.zone_name, dnssec=data.dnssec)
        )

    async def delete_master_zones(self, data: DNSServiceZoneDeleteRequest) -> None:
        """Delete DNS zones."""
        await self._service.delete_master_zones(data.zone_ids)

    async def check_forward_zone(self, data: DNSServiceForwardZoneCheckRequest) -> list[DNSForwardServerStatus]:
        """Check DNS forward zone for availability."""
        return await self._service.check_forward_zone(data.dns_server_ips)
