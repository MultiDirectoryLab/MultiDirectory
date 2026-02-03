"""DNS service for remote DNS server managing.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address

from dns.asyncquery import inbound_xfr as make_inbound_xfr, tcp as asynctcp
from dns.message import Message, make_query as make_dns_query
from dns.name import from_text
from dns.rdataclass import IN
from dns.rdatatype import AXFR
from dns.tsig import Key as TsigKey
from dns.update import Update
from dns.zone import Zone

from ldap_protocol.dns.dto import (
    DNSForwardServerStatus,
    DNSForwardZoneDTO,
    DNSMasterZoneDTO,
    DNSRecordDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
)
from ldap_protocol.dns.exceptions import (
    DNSConnectionError,
    DNSNotImplementedError,
)
from ldap_protocol.dns.managers.abstract_dns_manager import AbstractDNSManager
from ldap_protocol.dns.utils import logger_wraps


class RemoteDNSManager(AbstractDNSManager):
    """DNS server manager."""

    async def _send(self, action: Message) -> None:
        """Send request to DNS server."""
        if self._dns_settings.tsig_key is not None:
            action.use_tsig(
                keyring=TsigKey("zone.", self._dns_settings.tsig_key),
                keyname="zone.",
            )

        if self._dns_settings.dns_server_ip is None:
            raise DNSConnectionError

        await asynctcp(action, str(self._dns_settings.dns_server_ip))

    async def setup(
        self,
        dns_settings: DNSSettingsDTO,  # noqa: ARG002
    ) -> None:
        """Set up DNS server and DNS manager."""
        raise DNSNotImplementedError

    @logger_wraps()
    async def create_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None:
        """Create DNS record."""
        action = Update(self._dns_settings.domain or zone_id)
        action.add(
            record.name,
            record.ttl,
            record.type,
            record.records[0].content,
        )

        await self._send(action)

    @logger_wraps()
    async def get_records(self) -> list[DNSRRSetDTO]:
        """Get all DNS records."""
        if (
            self._dns_settings.dns_server_ip is None
            or self._dns_settings.domain is None
        ):
            raise DNSConnectionError

        zone = from_text(self._dns_settings.domain)
        zone_tm = Zone(zone)
        query = make_dns_query(zone, AXFR, IN)

        if self._dns_settings.tsig_key is not None:
            query.use_tsig(
                keyring=TsigKey("zone.", self._dns_settings.tsig_key),
                keyname="zone.",
            )

        await make_inbound_xfr(
            str(self._dns_settings.dns_server_ip),
            zone_tm,
        )

        return [
            DNSRRSetDTO(
                name=name.to_text() + f".{self._dns_settings.domain}.",
                type=rdata.rdtype.name,
                records=[
                    DNSRecordDTO(
                        content=rdata.to_text(),
                        disabled=False,
                    ),
                ],
                ttl=ttl,
            )
            for name, ttl, rdata in zone_tm.iterate_rdatas()
        ]

    @logger_wraps()
    async def update_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None:
        """Update DNS record."""
        action = Update(self._dns_settings.domain or zone_id)
        action.replace(
            record.name,
            record.ttl,
            record.type,
            record.records[0].content,
        )
        await self._send(action)

    @logger_wraps()
    async def delete_record(
        self,
        zone_id: str,
        record: DNSRRSetDTO,
    ) -> None:
        """Delete DNS record."""
        action = Update(self._dns_settings.domain or zone_id)
        action.delete(
            record.name,
            record.type,
            record.records[0].content,
        )
        await self._send(action)

    async def get_master_zones(self) -> list[DNSMasterZoneDTO]:
        raise DNSNotImplementedError

    async def get_forward_zones(self) -> list[DNSForwardZoneDTO]:
        raise DNSNotImplementedError

    async def create_master_zone(
        self,
        zone: DNSMasterZoneDTO,  # noqa: ARG002
    ) -> None:
        raise DNSNotImplementedError

    async def create_forward_zone(
        self,
        zone: DNSForwardZoneDTO,  # noqa: ARG002
    ) -> None:
        raise DNSNotImplementedError

    async def update_master_zone(
        self,
        zone: DNSMasterZoneDTO,  # noqa: ARG002
    ) -> None:
        raise DNSNotImplementedError

    async def update_forward_zone(
        self,
        zone: DNSForwardZoneDTO,  # noqa: ARG002
    ) -> None:
        raise DNSNotImplementedError

    async def delete_master_zone(
        self,
        zone_id: str,  # noqa: ARG002
    ) -> None:
        raise DNSNotImplementedError

    async def delete_forward_zone(
        self,
        zone_id: str,  # noqa: ARG002
    ) -> None:
        raise DNSNotImplementedError

    async def check_forward_dns_server(
        self,
        dns_server_ip: IPv4Address | IPv6Address,  # noqa: ARG002
        host_dns_servers: list[str],  # noqa: ARG002
    ) -> DNSForwardServerStatus:
        raise DNSNotImplementedError
