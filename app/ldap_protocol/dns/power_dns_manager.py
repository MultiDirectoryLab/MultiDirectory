"""PowerDNS API manager module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import re
from ipaddress import IPv4Address, IPv6Address

import dns.asyncresolver
import httpx
from adaptix import Retort
from dnsdist_console import Console
from fastapi import status

from config import Settings

from .base import (
    AbstractDNSHTTPClient,
    AbstractDNSManager,
    DNSForwarderServerStatus,
    DNSForwardServerStatus,
    DNSManagerSettings,
)
from .constants import DNS_FIRST_SETUP_RECORDS
from .dto import (
    DNSForwardZoneDTO,
    DNSMasterZoneDTO,
    DNSRecordDTO,
    DNSRRSetDTO,
    DNSSettingsDTO,
)
from .enums import DNSRecordType, PowerDNSRecordChangeType
from .exceptions import (
    DNSdistError,
    DNSEntryNotFoundError,
    DNSError,
    DNSNotSupportedError,
    DNSRecordCreateError,
    DNSRecordDeleteError,
    DNSRecordGetError,
    DNSRecordUpdateError,
    DNSSetupError,
    DNSUnavailableError,
    DNSValidationError,
    DNSZoneCreateError,
    DNSZoneDeleteError,
    DNSZoneGetError,
    DNSZoneUpdateError,
)
from .utils import create_initial_zone_records

base_retort = Retort()


class PowerDNSDistClient:
    """Client for dnsdist."""

    def __init__(
        self,
        dnsdist_host: str,
        dnsdist_port: int,
        dnsdist_key: str,
        config_path: str,
    ) -> None:
        self._console = Console(
            host=dnsdist_host,
            port=dnsdist_port,
            key=dnsdist_key,
        )
        self._config_path = config_path

    def _send_command(self, command: str) -> str:
        """Send command to dnsdist console."""
        return self._console.send_command(command)

    def _get_rule_id(self, match_rule: str) -> int | None:
        """Get rule ID from all rules list."""
        rules = self.get_all_rules()
        pattern = rf"^(\d+)\s+.*?\b{re.escape(match_rule)}\b"
        match = re.search(pattern, rules, re.MULTILINE)
        return int(match.group(1)) if match else None

    def get_all_rules(self) -> str:
        """Get list of all rules."""
        command = "showRules()"
        return self._send_command(command)

    def add_server(
        self,
        server_host: str | IPv4Address,
        pool: str,
    ) -> None:
        """Add server to dnsdist config."""
        command = f"""
            newServer({{
                address = "{server_host}:53",
                pool = "{pool}"
            }})
        """
        output = self._send_command(command)
        if len(output) > 1:
            raise DNSdistError(
                f"Failed to add server to dnsdist: {len(output)}",
            )

        self._persist_config()

    def setup_dnsdist(self, recursor_ip: str) -> None:
        """Set up dnsdist with initial configuration."""
        command = f"""
            newServer({{
                address = "{recursor_ip}:53",
                pool = "recursor"
            }})
        """
        self._send_command(command)

        command = """
            addAction(
                AllRule(),
                PoolAction("recursor")
            )
        """
        output = self._send_command(command)
        if len(output) > 1:
            raise DNSdistError(f"Failed to add rule to dnsdist: {output}")

    def add_zone_rule(self, domain: str) -> None:
        """Add rule to redirect master zone DNS requests to auth server."""
        command = f"""
            addAction(
                QNameRule("*.{domain}"),
                PoolAction("master")
            )
        """
        output = self._send_command(command)
        if len(output) > 1:
            raise DNSdistError(f"Failed to add rule to dnsdist: {output}")

        command = f"""
            addAction(
                QNameRule("{domain}"),
                PoolAction("master")
            )
        """
        output = self._send_command(command)
        if output:
            raise DNSdistError(f"Failed to add rule to dnsdist: {output}")

        self._deprioritize_all_match_rule()

        self._persist_config()

    def remove_zone_rule(self, domain: str) -> None:
        """Remove redirect rule from dnsdist."""
        rule_matches = [
            f"qname=={domain}",
            f"qname==*.{domain}",
        ]
        rule_ids = [
            self._get_rule_id(rule_match) for rule_match in rule_matches
        ]
        if not rule_ids:
            DNSdistError(
                "Failed to delete existing rule in dnsdist: Not Found",
            )

        for rule_id in rule_ids:
            command = f"rmRule({rule_id})"
            output = self._send_command(command)
            if len(output) > 1:
                raise DNSdistError(f"Failed to add rule to dnsdist: {output}")

        self._persist_config()

    def _deprioritize_all_match_rule(self) -> None:
        """Remove and add all matching rule to depriortitize it."""
        rule_id = self._get_rule_id("All")
        if rule_id is None:
            return

        command = f"rmRule({rule_id})"
        self._send_command(command)

        command = """
            addAction(
                AllRule(),
                PoolAction("recursor")
            )
        """
        self._send_command(command)

        self._persist_config()

    def _get_commands_delta(self) -> list[str]:
        """Get list of commands that have not been persisted yet."""
        command = "delta()"
        output = self._send_command(command)
        commands = output.strip().split("\n") if output else []
        return commands

    def _save_commands_delta(self, commands: list[str]) -> None:
        """Save commands delta to dnsdist config file."""
        with open(self._config_path, "a+", encoding="utf-8") as config_file:
            for command in commands:
                config_file.write(f"{command}\n")

    def _clear_console_history(self) -> None:
        """Clear console history to delete written delta."""
        command = "clearConsoleHistory()"
        self._send_command(command)

    def _persist_config(self) -> None:
        """Persist dnsdist config to file."""
        commands_delta = self._get_commands_delta()
        if commands_delta:
            self._save_commands_delta(commands_delta)

        self._clear_console_history()


class PowerDNSHTTPClient(AbstractDNSHTTPClient):
    """HTTTP client for PowerDNS."""

    _http_client: httpx.AsyncClient

    def __init__(
        self,
        server_host: str,
        server_port: int,
        api_key: str,
    ) -> None:
        """Initialize the PowerDNS HTTP client."""
        self._http_client = httpx.AsyncClient(
            base_url=f"http://{server_host}:{server_port}/api/v1/servers/localhost",
            headers={"X-API-Key": api_key},
        )

    async def _validate_response(self, response: httpx.Response) -> None:
        """Validate the API response."""
        match response.status_code:
            case status.HTTP_400_BAD_REQUEST:
                raise DNSNotSupportedError(response.text or "Bad Request")
            case status.HTTP_404_NOT_FOUND:
                raise DNSEntryNotFoundError(response.text or "Not Found")
            case status.HTTP_422_UNPROCESSABLE_ENTITY:
                raise DNSValidationError(
                    response.text or "Unprocessable Entity",
                )
            case status.HTTP_500_INTERNAL_SERVER_ERROR:
                raise DNSUnavailableError(
                    response.text or "Internal Server Error",
                )

    async def send(
        self,
        method: str,
        url: str,
        payload: dict | None = None,
    ) -> httpx.Response:
        """Get the recursor DNS HTTP client."""
        response = await self._http_client.request(
            method=method,
            url=url,
            json=payload,
        )

        await self._validate_response(response)

        return response


class PowerDNSManager(AbstractDNSManager):
    """Manager for interacting with the PowerDNS API."""

    _power_dns_auth_client: AbstractDNSHTTPClient
    _power_dns_recursor_client: AbstractDNSHTTPClient
    _dnsdist_client: PowerDNSDistClient

    def __init__(
        self,
        settings: DNSManagerSettings,
        app_settings: Settings,
    ) -> None:
        """Initialize the PowerDNS API repository."""
        super().__init__(settings, app_settings)
        self._power_dns_auth_client = self._setup_client(
            self._app_settings.PDNS_AUTH_SERVER_HOST,
            self._app_settings.PDNS_AUTH_SERVER_PORT,
            self._app_settings.PDNS_API_KEY,
        )
        self._power_dns_recursor_client = self._setup_client(
            self._app_settings.PDNS_RECURSOR_SERVER_HOST,
            self._app_settings.PDNS_RECURSOR_SERVER_PORT,
            self._app_settings.PDNS_API_KEY,
        )
        self._dnsdist_client = self._setup_dnsdist(
            self._app_settings.PDNS_DIST_HOST,
            self._app_settings.PDNS_DIST_PORT,
            self._app_settings.PDNS_DIST_KEY,
            self._app_settings.PDNS_DIST_CONFIG_PATH,
        )

    def _setup_dnsdist(
        self,
        dnsdist_host: str,
        dnsdist_port: int,
        dnsdist_key: str,
        config_path: str,
    ) -> PowerDNSDistClient:
        """Set up dnsdist controller."""
        return PowerDNSDistClient(
            dnsdist_host=dnsdist_host,
            dnsdist_port=dnsdist_port,
            dnsdist_key=dnsdist_key,
            config_path=config_path,
        )

    def _setup_client(
        self,
        server_host: str,
        server_port: int,
        api_key: str,
    ) -> AbstractDNSHTTPClient:
        """Set up HTTP clients for PowerDNS."""
        return PowerDNSHTTPClient(
            server_host=server_host,
            server_port=server_port,
            api_key=api_key,
        )

    @staticmethod
    def _normalize_dns_name(name: str) -> str:
        """Normalize DNS name by ensuring it ends with a dot."""
        return name if name.endswith(".") else f"{name}."

    async def setup(self, dns_server_settings: DNSSettingsDTO) -> None:
        """Set up DNS server and DNS manager."""
        records = []

        for record in DNS_FIRST_SETUP_RECORDS:
            records.append(
                DNSRRSetDTO(
                    name=f"{record['name']}{dns_server_settings.domain}.",
                    type=DNSRecordType(record["type"]),
                    records=[
                        DNSRecordDTO(
                            content=f"{record['value']}{dns_server_settings.domain}.",
                            disabled=False,
                            modified_at=None,
                        ),
                    ],
                    changetype=PowerDNSRecordChangeType.EXTEND,
                    ttl=3600,
                ),
            )

        try:
            await self.create_master_zone(
                DNSMasterZoneDTO(
                    id=dns_server_settings.domain,
                    name=dns_server_settings.domain,
                    dnssec=False,
                    rrsets=records,
                ),
            )
            self._dnsdist_client.setup_dnsdist(
                self._app_settings.PDNS_RECURSOR_SERVER_IP,
            )
            self._dnsdist_client.add_server(
                self._app_settings.PDNS_AUTH_SERVER_IP,
                "master",
            )
        except DNSZoneCreateError as e:
            raise DNSSetupError(f"Failed to set up DNS: {e}")

    async def create_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Create a DNS record in the specified zone."""
        record.name = self._normalize_dns_name(record.name)

        record.changetype = PowerDNSRecordChangeType.REPLACE

        try:
            await self._power_dns_auth_client.send(
                method="PATCH",
                url=f"/zones/{zone_id}",
                payload={"rrsets": [base_retort.dump(record)]},
            )
        except DNSError as e:
            raise DNSRecordCreateError(f"Failed to create DNS record: {e}")

    async def get_records(self, zone_id: str) -> list[DNSRRSetDTO]:
        """Retrieve all DNS records for the specified zone."""
        try:
            response = await self._power_dns_auth_client.send(
                method="GET",
                url=f"/zones/{zone_id}",
            )
        except DNSError as e:
            raise DNSRecordGetError(f"Failed to get DNS records: {e}")

        zone = base_retort.load(response.json(), DNSMasterZoneDTO)

        return zone.rrsets

    async def update_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Update a DNS record in the specified zone."""
        record.name = self._normalize_dns_name(record.name)

        record.changetype = PowerDNSRecordChangeType.REPLACE

        try:
            await self._power_dns_auth_client.send(
                method="PATCH",
                url=f"/zones/{zone_id}",
                payload={"rrsets": [base_retort.dump(record)]},
            )
        except DNSError as e:
            raise DNSRecordUpdateError(f"Failed to update DNS record: {e}")

    async def delete_record(self, zone_id: str, record: DNSRRSetDTO) -> None:
        """Delete a DNS record from the specified zone."""
        record.name = self._normalize_dns_name(record.name)

        record.changetype = PowerDNSRecordChangeType.DELETE

        try:
            await self._power_dns_auth_client.send(
                method="PATCH",
                url=f"/zones/{zone_id}",
                payload={"rrsets": [base_retort.dump(record)]},
            )
        except DNSError as e:
            raise DNSRecordDeleteError(f"Failed to delete DNS record: {e}")

    async def create_master_zone(self, zone: DNSMasterZoneDTO) -> None:
        """Create a master DNS zone."""
        zone.name = self._normalize_dns_name(zone.name)

        zone.nameservers.append(f"ns1.{zone.name}")

        records = await create_initial_zone_records(
            zone.name,
            self._app_settings.DEFAULT_NAMESERVER,
        )
        zone.rrsets.extend(records)

        try:
            await self._power_dns_auth_client.send(
                method="POST",
                url="/zones",
                payload=base_retort.dump(zone),
            )
            self._dnsdist_client.add_zone_rule(
                zone.name if not zone.name.endswith(".") else zone.name[:-1],
            )
        except DNSError as e:
            raise DNSZoneCreateError(f"Failed to create DNS zone: {e}")

    async def create_forward_zone(self, zone: DNSForwardZoneDTO) -> None:
        """Create a forward DNS zone."""
        zone.name = self._normalize_dns_name(zone.name)

        try:
            await self._power_dns_recursor_client.send(
                method="POST",
                url="/zones",
                payload=base_retort.dump(zone),
            )
        except DNSError as e:
            raise DNSZoneCreateError(f"Failed to create DNS zone: {e}")

    async def get_master_zones(self) -> list[DNSMasterZoneDTO]:
        """Retrieve all DNS zones."""
        try:
            response = await self._power_dns_auth_client.send(
                method="GET",
                url="/zones",
            )
        except DNSError as e:
            raise DNSZoneGetError(f"Failed to get DNS zones: {e}")

        zones = base_retort.load(response.json(), list[DNSMasterZoneDTO])
        for zone in zones:
            zone.rrsets = await self.get_records(zone.id)

        return zones

    async def get_master_zone_by_id(self, zone_id: str) -> DNSMasterZoneDTO:
        """Get master DNS zone by ID."""
        try:
            response = await self._power_dns_auth_client.send(
                method="GET",
                url=f"/zones/{zone_id}",
            )
        except DNSError as e:
            raise DNSZoneGetError(f"Failed to get DNS zones: {e}")

        return base_retort.load(response.json(), DNSMasterZoneDTO)

    async def get_forward_zones(self) -> list[DNSForwardZoneDTO]:
        """Retrieve all forward DNS zones."""
        try:
            response = await self._power_dns_recursor_client.send(
                method="GET",
                url="/zones",
            )
        except DNSError as e:
            raise DNSZoneGetError(f"Failed to get DNS zones: {e}")

        zones = base_retort.load(response.json(), list[DNSForwardZoneDTO])

        return zones

    async def update_master_zone(self, zone: DNSMasterZoneDTO) -> None:
        """Update a master DNS zone."""
        zone.name = self._normalize_dns_name(zone.name)
        try:
            await self._power_dns_auth_client.send(
                method="PUT",
                url=f"/zones/{zone.id}",
                payload=base_retort.dump(zone),
            )
        except DNSError as e:
            raise DNSZoneUpdateError(f"Failed to update DNS zone: {e}")

    async def update_forward_zone(self, zone: DNSForwardZoneDTO) -> None:
        """Update a forward DNS zone."""
        zone.name = self._normalize_dns_name(zone.name)

        try:
            await self._power_dns_recursor_client.send(
                method="PUT",
                url=f"/zones/{zone.id}",
                payload=base_retort.dump(zone),
            )
        except DNSError as e:
            raise DNSZoneUpdateError(f"Failed to update DNS zone: {e}")

    async def delete_master_zone(self, zone_id: str) -> None:
        """Delete a DNS zone."""
        zone = await self.get_master_zone_by_id(zone_id)

        try:
            await self._power_dns_auth_client.send(
                method="DELETE",
                url=f"/zones/{zone_id}",
            )
            self._dnsdist_client.remove_zone_rule(zone.name)
        except DNSError as e:
            raise DNSZoneDeleteError(f"Failed to delete DNS zone: {e}")

    async def delete_forward_zone(self, zone_id: str) -> None:
        """Delete a DNS forward zone."""
        try:
            await self._power_dns_recursor_client.send(
                method="DELETE",
                url=f"/zones/{zone_id}",
            )
        except DNSError as e:
            raise DNSZoneDeleteError(f"Failed to delete DNS zone: {e}")

    async def find_forward_dns_fqdn(
        self,
        dns_server_ip: IPv4Address | IPv6Address,
        host_dns_servers: list[str],
    ) -> str | None:
        """Find forward DNS FQDN."""
        reversed_ip = (
            ".".join(reversed((str(dns_server_ip)).split(".")))
            + ".in-addr.arpa"
        )

        async def get_fqdn_and_latency(
            server: str,
        ) -> tuple[float, str | None]:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = [server]
            resolver.timeout = 10

            try:
                event_loop = asyncio.get_running_loop()
                start_time = event_loop.time()
                fqdn = await resolver.resolve(reversed_ip, DNSRecordType.PTR)
                latency = event_loop.time() - start_time

                return (latency, fqdn[0].to_text())
            except (
                dns.asyncresolver.NoAnswer,
                dns.asyncresolver.NXDOMAIN,
            ):
                return (float("inf"), None)

        fqdn_list = await asyncio.gather(
            *(get_fqdn_and_latency(server) for server in host_dns_servers),
        )
        fqdn_list.sort(key=lambda x: x[0])
        return fqdn_list[0][1] if fqdn_list else None

    async def check_forward_dns_server(
        self,
        dns_server_ip: IPv4Address | IPv6Address,
        host_dns_servers: list[str],
    ) -> DNSForwardServerStatus:
        str_dns_server_ip = str(dns_server_ip)

        try:
            fqdn = await self.find_forward_dns_fqdn(
                dns_server_ip,
                host_dns_servers,
            )
        except (dns.asyncresolver.NoAnswer, dns.asyncresolver.NXDOMAIN):
            return DNSForwardServerStatus(
                str_dns_server_ip,
                DNSForwarderServerStatus.NOT_VALIDATED,
                None,
            )

        if not fqdn:
            return DNSForwardServerStatus(
                str_dns_server_ip,
                DNSForwarderServerStatus.NOT_FOUND,
                None,
            )

        return DNSForwardServerStatus(
            str_dns_server_ip,
            DNSForwarderServerStatus.VALIDATED,
            fqdn,
        )
