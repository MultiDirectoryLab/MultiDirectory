"""Manager for migrating from BIND to PowerDNS.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import os

import dns.zone

from app.ldap_protocol.dns.dto import DNSSettingsDTO
from app.ldap_protocol.dns.managers.power_dns_manager import PowerDNSManager


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

    def parse_bind_config_file(self) -> dict[str, list[str]]:
        """Parse BIND configuration files to extract zone information."""
        zones = {"master": [], "forward": []}

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
                    zones["master"].append(zone_name)
                elif "type forward" in line:
                    zones["forward"].append(zone_name)

        return zones

    def parse_zones_records(
        self,
        zones: dict[str, list[str]],
    ) -> dict[str, list[dict]]:
        """Parse zone files to extract DNS records."""
        records = {"master": {}, "forward": {}}

        for zone_type, zone_names in zones.items():
            for zone_name in zone_names:
                zone_file_path = os.path.join(
                    self.bind_zone_file_dir,
                    f"{zone_name}.zone",
                )
                zones[zone_type][zone_name] = []
                zone_obj = dns.zone.from_file(zone_file_path, origin=zone_name)
                for name, ttl, rdata in zone_obj.iterate_rdatas():
                    record = {
                        "name": name.to_text(),
                        "ttl": ttl,
                        "type": rdata.rdtype,
                        "rdata": rdata.to_text(),
                    }
                    records[zone_type][zone_name].append(record)

        return zones

    async def get_bind_zones(self) -> dict[str, list[str]]:
        """Get zones from BIND."""
        zones = self.parse_bind_config_file()
        zones = self.parse_zones_records(zones)

        return zones

    async def migrate_from_bind(self) -> None:
        """Migrate from BIND to PowerDNS."""
        bind_zones = await self.get_bind_zones()

        for zone in bind_zones["master"]:
            await self.pdns_manager.create_master_zone(zone)

        for zone in bind_zones["forward"]:
            await self.pdns_manager.create_forward_zone(zone)

        # Create migration marker files
        open(os.path.join(self.bind_zone_file_dir, "migrated"), "a").close()
        open(os.path.join(self.bind_config_files_dir, "migrated"), "a").close()

    def is_migration_needed(self) -> bool:
        """Check if migration is needed."""
        return not (
            os.path.exists(os.path.join(self.bind_zone_file_dir, "migrated"))
            and os.path.exists(
                os.path.join(self.bind_config_files_dir, "migrated"),
            )
        )

    async def migrate(self) -> None:
        """Migrate from BIND to PowerDNS."""
        if not self.is_migration_needed():
            return

        await self.pdns_manager.setup(self.dns_settings)

        await self.migrate_from_bind()
