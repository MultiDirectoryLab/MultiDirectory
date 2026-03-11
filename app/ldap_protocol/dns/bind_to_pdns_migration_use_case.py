"""Manager for migrating from BIND to PowerDNS.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import os

import dns.zone
from loguru import logger

from ldap_protocol.dns.dto import (
    DNSForwardZoneDTO,
    DNSMasterZoneDTO,
    DNSRecordDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
)
from ldap_protocol.dns.enums import DNSRecordType
from ldap_protocol.dns.managers.power_dns_manager import PowerDNSManager


class BindToPDNSMigrationUseCase:
    bind_zone_file_dir: str = "/opt/"
    bind_config_files_dir: str = "/etc/bind/"

    def __init__(
        self,
        pdns_manager: PowerDNSManager,
        dns_settings: DNSSettingsDTO,
    ) -> None:
        self.pdns_manager = pdns_manager
        self.dns_settings = dns_settings

    def _strip_record_name(self, record_name: str, zone_name: str) -> str:
        """Strip trash from record name."""
        logger.debug(
            f"Stripping record name '{record_name}' for zone '{zone_name}'",
        )
        if record_name.startswith(("\\032", "\\@")) and record_name != "\\@":
            record_name = record_name.removeprefix("\\032").removeprefix("\\@")
        elif record_name == "\\@":
            record_name = zone_name
        return (
            record_name if not record_name.startswith(".") else record_name[1:]
        )

    def parse_bind_config_file(
        self,
    ) -> tuple[list[DNSMasterZoneDTO], list[DNSForwardZoneDTO]]:
        """Parse BIND configuration files to extract zone information."""
        master_zones: list[DNSMasterZoneDTO] = []
        forward_zones: list[DNSForwardZoneDTO] = []

        with open(
            os.path.join(self.bind_config_files_dir, "named.conf.local"),
        ) as f:
            for line in f:
                line = line.strip()
                if line.startswith("zone"):
                    parts = line.split()
                    if len(parts) >= 2:
                        zone_name = parts[1].strip('"')
                        continue

                if "type master" in line:
                    master_zones.append(
                        DNSMasterZoneDTO(
                            id=zone_name,
                            name=zone_name,
                        ),
                    )
                elif "type forward" in line:
                    forward_zone = DNSForwardZoneDTO(
                        id=zone_name,
                        name=zone_name,
                    )
                elif "forwarders" in line and forward_zone:
                    forwarders_part = line.split("forwarders")[1]
                    forwarders = [
                        f
                        for f in forwarders_part.strip(";")
                        .strip(" ")
                        .strip("{")
                        .strip("}")
                        .strip(" ")
                        .split(";")[:-1]
                    ]
                    forward_zone.servers = forwarders
                    forward_zones.append(forward_zone)
                    forward_zone = None

        return master_zones, forward_zones

    def parse_zones_records(
        self,
        master_zones: list[DNSMasterZoneDTO],
    ) -> list[DNSMasterZoneDTO]:
        """Parse zone files to extract DNS records."""
        zones_with_records: list[DNSMasterZoneDTO] = []

        for zone in master_zones:
            zone_rrsets: list[DNSRRSetDTO] = []
            zone_file_path = os.path.join(
                self.bind_zone_file_dir,
                f"{zone.name}.zone",
            )
            try:
                zone_obj = dns.zone.from_file(
                    zone_file_path,
                    origin=zone.name,
                    relativize=False,
                )
            except FileNotFoundError:
                logger.error(
                    f"Zone file for zone {zone.name} not found, skipping...",
                )
                continue

            for name, ttl, rdata in zone_obj.iterate_rdatas():
                try:
                    record_type = DNSRecordType(rdata.rdtype.name)
                except ValueError:
                    logger.warning(
                        f"Unsupported DNS record type {rdata.rdtype.name} in zone '{zone.name}'",  # noqa: E501
                    )
                    continue

                zone_rrsets.append(
                    DNSRRSetDTO(
                        name=self._strip_record_name(
                            name.to_text(),
                            zone.name,
                        ),
                        type=record_type,
                        records=[
                            DNSRecordDTO(
                                content=rdata.to_text(),
                                disabled=False,
                            ),
                        ],
                        ttl=ttl,
                    ),
                )
            zone.rrsets = zone_rrsets
            zones_with_records.append(zone)

        return zones_with_records

    async def get_bind_zones(
        self,
    ) -> tuple[list[DNSMasterZoneDTO], list[DNSForwardZoneDTO]]:
        """Get zones from BIND."""
        master_zones, forward_zones = self.parse_bind_config_file()
        master_zones = self.parse_zones_records(master_zones)

        return master_zones, forward_zones

    async def migrate_from_bind(self) -> None:
        """Migrate from BIND to PowerDNS."""
        master_zones, forward_zones = await self.get_bind_zones()

        for master_zone in master_zones:
            await self.pdns_manager.create_master_zone(
                master_zone,
                is_empty=True,
            )
            for rrset in master_zone.rrsets:
                await self.pdns_manager.create_record(
                    master_zone.name,
                    rrset,
                )

        for forward_zone in forward_zones:
            await self.pdns_manager.create_forward_zone(forward_zone)

        open(os.path.join(self.bind_zone_file_dir, "migrated"), "a").close()
        open(os.path.join(self.bind_config_files_dir, "migrated"), "a").close()

    def is_migration_needed(self) -> bool:
        """Check if migration is needed."""
        return not (
            os.path.exists(os.path.join(self.bind_zone_file_dir, "migrated"))
            and os.path.exists(
                os.path.join(self.bind_config_files_dir, "migrated"),
            )
        ) and bool(os.listdir(self.bind_zone_file_dir))

    async def migrate(self) -> None:
        """Migrate from BIND to PowerDNS."""
        if not self.is_migration_needed():
            logger.info("BIND to PowerDNS migration is not needed, exiting...")
            return

        logger.info("Starting BIND to PowerDNS migration...")
        await self.pdns_manager.setup(self.dns_settings, is_migration=True)

        await self.migrate_from_bind()
        logger.info("Migration successful")
        return
