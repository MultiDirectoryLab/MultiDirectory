"""Clinet for Power dnsdist service.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from ipaddress import IPv4Address

from dnsdist_console import Console

from ldap_protocol.dns.exceptions import DNSdistError


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

    # TODO: присобачить нормальный тип возвращаемого значения
    def _send_command(self, command: str) -> str:
        """Send command to dnsdist console."""
        return self._console.send_command(command)

    def _get_rule_id(self, match_rule: str) -> int | None:
        """Get rule ID from all rules list."""
        rules = self.get_all_rules()
        pattern = rf"^(\d+)\s+.*?\b{re.escape(match_rule)}\b"
        match = re.search(pattern, rules, re.MULTILINE)
        return int(match.group(1)) if match else None

    # TODO: тоже присобачить нормальный тип возвращаемого значения
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
        if len(output) > 1:
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
        if commands_delta := self._get_commands_delta():
            self._save_commands_delta(commands_delta)

        self._clear_console_history()
