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


class BindToPDNSMigrationManager:
    bind_zone_file_dir: str = "/opt/"
    bind_config_files_dir: str = "/etc/bind/"

    def __init__(
        self,
        pdns_manager: PowerDNSManager,
        dns_settings: DNSSettingsDTO,
    ) -> None:
        self.pdns_manager = pdns_manager
        self.dns_settings = dns_settings

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
                    forward_zones.append(
                        DNSForwardZoneDTO(
                            id=zone_name,
                            name=zone_name,
                        ),
                    )

        return master_zones, forward_zones

    def parse_zones_records(
        self,
        master_zones: list[DNSMasterZoneDTO],
    ) -> list[DNSMasterZoneDTO]:
        """Parse zone files to extract DNS records."""
        for zone in master_zones:
            zone_rrsets: list[DNSRRSetDTO] = []
            zone_file_path = os.path.join(
                self.bind_zone_file_dir,
                f"{zone.name}.zone",
            )
            zone_obj = dns.zone.from_file(
                zone_file_path,
                origin=zone.name,
                relativize=False,
            )
            for name, ttl, rdata in zone_obj.iterate_rdatas():
                try:
                    DNSRecordType(rdata.rdtype.name)
                except ValueError:
                    logger.warning(
                        f"Unsupported DNS record type {rdata.rdtype.name} in zone '{zone.name}'",  # noqa: E501
                    )
                    continue

                zone_rrsets.append(
                    DNSRRSetDTO(
                        name=name.to_text(),
                        type=DNSRecordType(rdata.rdtype.name),
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

        return master_zones

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
        await self.pdns_manager.setup(self.dns_settings)

        await self.migrate_from_bind()
        logger.info("Migration successful")
        return
