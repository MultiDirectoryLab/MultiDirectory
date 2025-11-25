"""DNS adapter.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import status

import ldap_protocol.dns.exceptions as dns_exc
from api.base_adapter import BaseAdapter
from api.main.schema import (
    DNSServiceForwardZoneCheckRequest,
    DNSServiceRecordCreateRequest,
    DNSServiceRecordDeleteRequest,
    DNSServiceRecordUpdateRequest,
    DNSServiceReloadZoneRequest,
    DNSServiceSetupRequest,
    DNSServiceZoneCreateRequest,
    DNSServiceZoneDeleteRequest,
    DNSServiceZoneUpdateRequest,
)
from ldap_protocol.dns.base import (
    DNSForwardServerStatus,
    DNSForwardZone,
    DNSRecords,
    DNSServerParam,
    DNSZone,
)
from ldap_protocol.dns.use_cases import DNSUseCase


class DNSFastAPIAdapter(BaseAdapter[DNSUseCase]):
    """DNS adapter."""

    _exceptions_map = {
        dns_exc.DNSSetupError: status.HTTP_424_FAILED_DEPENDENCY,
        dns_exc.DNSRecordCreateError: status.HTTP_400_BAD_REQUEST,
        dns_exc.DNSRecordUpdateError: status.HTTP_400_BAD_REQUEST,
        dns_exc.DNSRecordDeleteError: status.HTTP_400_BAD_REQUEST,
        dns_exc.DNSZoneCreateError: status.HTTP_400_BAD_REQUEST,
        dns_exc.DNSZoneUpdateError: status.HTTP_400_BAD_REQUEST,
        dns_exc.DNSZoneDeleteError: status.HTTP_400_BAD_REQUEST,
        dns_exc.DNSUpdateServerOptionsError: status.HTTP_400_BAD_REQUEST,
    }

    async def create_record(
        self,
        data: DNSServiceRecordCreateRequest,
    ) -> None:
        """Create DNS record."""
        await self._service.create_record(
            data.record_name,
            data.record_value,
            data.record_type,
            data.ttl,
            data.zone_name,
        )

    async def delete_record(
        self,
        data: DNSServiceRecordDeleteRequest,
    ) -> None:
        """Delete DNS record."""
        await self._service.delete_record(
            data.record_name,
            data.record_value,
            data.record_type,
            data.zone_name,
        )

    async def update_record(
        self,
        data: DNSServiceRecordUpdateRequest,
    ) -> None:
        """Update DNS record."""
        await self._service.update_record(
            data.record_name,
            data.record_value,
            data.record_type,
            data.ttl,
            data.zone_name,
        )

    async def get_all_records(self) -> list[DNSRecords]:
        """Get all DNS records of current zone."""
        return await self._service.get_all_records()

    async def get_dns_status(self) -> dict[str, str | None]:
        """Get DNS service status."""
        return await self._service.get_dns_status()

    async def setup_dns(self, data: DNSServiceSetupRequest) -> None:
        await self._service.setup_dns(
            dns_status=data.dns_status,
            domain=data.domain,
            dns_ip_address=data.dns_ip_address,
            tsig_key=data.tsig_key,
        )

    async def get_dns_zone(self) -> list[DNSZone]:
        """Get all DNS zones."""
        return await self._service.get_all_zones_records()

    async def get_forward_dns_zones(self) -> list[DNSForwardZone]:
        """Get list of DNS forward zones with forwarders."""
        return await self._service.get_forward_zones()

    async def create_zone(self, data: DNSServiceZoneCreateRequest) -> None:
        """Create new DNS zone."""
        await self._service.create_zone(
            data.zone_name,
            data.zone_type,
            data.nameserver,
            data.params,
        )

    async def update_zone(self, data: DNSServiceZoneUpdateRequest) -> None:
        """Update DNS zone with given params."""
        await self._service.update_zone(
            data.zone_name,
            data.params,
        )

    async def delete_zone(self, data: DNSServiceZoneDeleteRequest) -> None:
        """Delete DNS zone."""
        await self._service.delete_zone(data.zone_names)

    async def check_dns_forward_zone(
        self,
        data: DNSServiceForwardZoneCheckRequest,
    ) -> list[DNSForwardServerStatus]:
        """Check DNS forward zone for availability."""
        return await self._service.check_dns_forward_zone(data.dns_server_ips)

    async def reload_zone(self, data: DNSServiceReloadZoneRequest) -> None:
        """Reload DNS zone."""
        await self._service.reload_zone(data.zone_name)

    async def update_server_options(
        self,
        data: list[DNSServerParam],
    ) -> None:
        """Update DNS server options."""
        await self._service.update_server_options(data)

    async def get_server_options(self) -> list[DNSServerParam]:
        """Get list of modifiable DNS server params."""
        return await self._service.get_server_options()

    async def restart_server(self) -> None:
        """Restart DNS server."""
        await self._service.restart_server()
