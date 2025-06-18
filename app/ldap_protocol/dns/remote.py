"""DNS service for remote DNS server managing.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from collections import defaultdict

from dns.asyncquery import inbound_xfr as make_inbound_xfr, tcp as asynctcp
from dns.message import Message, make_query as make_dns_query
from dns.name import from_text
from dns.rdataclass import IN
from dns.rdatatype import AXFR
from dns.tsig import Key as TsigKey
from dns.update import Update
from dns.zone import Zone

from .base import (
    AbstractDNSManager,
    DNSConnectionError,
    DNSForwardServerStatus,
    DNSForwardZone,
    DNSRecord,
    DNSRecords,
    DNSServerParam,
    DNSZone,
    DNSZoneParam,
    DNSZoneType,
)
from .utils import logger_wraps


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

        await asynctcp(action, self._dns_settings.dns_server_ip)

    @logger_wraps()
    async def create_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None:
        """Create DNS record."""
        action = Update(self._dns_settings.zone_name or zone_name)
        action.add(hostname, ttl, record_type, ip)

        await self._send(action)

    @logger_wraps()
    async def get_all_records(self) -> list[DNSRecords]:
        """Get all DNS records."""
        if (
            self._dns_settings.dns_server_ip is None
            or self._dns_settings.zone_name is None
        ):
            raise DNSConnectionError

        zone = from_text(self._dns_settings.zone_name)
        zone_tm = Zone(zone)
        query = make_dns_query(zone, AXFR, IN)

        if self._dns_settings.tsig_key is not None:
            query.use_tsig(
                keyring=TsigKey("zone.", self._dns_settings.tsig_key),
                keyname="zone.",
            )

        await make_inbound_xfr(
            self._dns_settings.dns_server_ip,
            zone_tm,
        )

        result: defaultdict[str, list] = defaultdict(list)
        for name, ttl, rdata in zone_tm.iterate_rdatas():
            record_type = rdata.rdtype.name

            if record_type == "SOA":
                continue

            result[record_type].append(
                DNSRecord(
                    name=(name.to_text() + f".{self._dns_settings.zone_name}"),
                    value=rdata.to_text(),
                    ttl=ttl,
                )
            )

        return [
            DNSRecords(type=record_type, records=records)
            for record_type, records in result.items()
        ]

    @logger_wraps()
    async def update_record(
        self,
        hostname: str,
        ip: str | None,
        record_type: str,
        ttl: int | None,
        zone_name: str | None = None,
    ) -> None:
        """Update DNS record."""
        action = Update(self._dns_settings.zone_name or zone_name)
        action.replace(hostname, ttl, record_type, ip)

        await self._send(action)

    @logger_wraps()
    async def delete_record(
        self,
        hostname: str,
        ip: str,
        record_type: str,
        zone_name: str | None = None,
    ) -> None:
        """Delete DNS record."""
        action = Update(self._dns_settings.zone_name or zone_name)
        action.delete(hostname, record_type, ip)

        await self._send(action)

    @logger_wraps()
    async def get_forward_zones(self) -> list[DNSForwardZone]:
        raise NotImplementedError

    @logger_wraps()
    async def get_all_zones_records(self) -> list[DNSZone]:
        raise NotImplementedError

    @logger_wraps()
    async def create_zone(
        self,
        zone_name: str,
        zone_type: DNSZoneType,
        nameserver: str | None,
        params: list[DNSZoneParam],
    ) -> None:
        raise NotImplementedError

    @logger_wraps()
    async def update_zone(
        self,
        zone_name: str,
        params: list[DNSZoneParam] | None,
    ) -> None:
        raise NotImplementedError

    @logger_wraps()
    async def delete_zone(
        self,
        zone_names: list[str],
    ) -> None:
        raise NotImplementedError

    @logger_wraps()
    async def check_forward_dns_server(
        self,
        dns_server_ip: str,
    ) -> DNSForwardServerStatus:
        raise NotImplementedError

    @logger_wraps()
    async def update_server_options(
        self,
        params: list[DNSServerParam],
    ) -> None:
        raise NotImplementedError

    @logger_wraps()
    async def get_server_options(self) -> list[DNSServerParam]:
        raise NotImplementedError

    @logger_wraps()
    async def restart_server(
        self,
    ) -> None:
        raise NotImplementedError

    @logger_wraps()
    async def reload_zone(
        self,
        zone_name: str,
    ) -> None:
        raise NotImplementedError
