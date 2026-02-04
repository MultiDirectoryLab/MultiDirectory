"""Clinet for Power dnsdist service.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from ipaddress import IPv4Address
from typing import Literal, overload

from dnsdist_console import Console

from ldap_protocol.dns.dto import (
    CommandResponse,
    DNSdistCommand,
    DNSdistCommandsDelta,
    DNSdistRulesTable,
    RuleEntry,
)
from ldap_protocol.dns.enums import DNSdistCommandType
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

    @overload
    def _send_command(
        self,
        command: str,
        *,
        expected: Literal[DNSdistCommandType.GENERIC],
    ) -> CommandResponse: ...

    @overload
    def _send_command(
        self,
        command: str,
        *,
        expected: Literal[DNSdistCommandType.SHOW_RULES],
    ) -> DNSdistRulesTable: ...

    @overload
    def _send_command(
        self,
        command: str,
        *,
        expected: Literal[DNSdistCommandType.COMMANDS_DELTA],
    ) -> DNSdistCommandsDelta: ...

    def _send_command(
        self,
        command: str,
        *,
        expected: DNSdistCommandType = DNSdistCommandType.GENERIC,
    ) -> CommandResponse | DNSdistRulesTable | DNSdistCommandsDelta:
        """Send command to dnsdist console."""
        raw: str = self._console.send_command(command)

        if expected is DNSdistCommandType.GENERIC:
            if "error" in raw.lower() or "fail" in raw.lower():
                raise DNSdistError(f"dnsdist command error: {raw.strip()}")
            return CommandResponse(message=raw.strip() or "OK")

        if expected is DNSdistCommandType.SHOW_RULES:
            rules = []
            pattern = re.compile(r"^(\d+)\s+\d+\s+(.+?)\s{2,}(to .+)$")
            for line in raw.strip().split("\n"):
                if "to pool" in line:
                    matches = pattern.match(line)
                    if matches:
                        rules.append(
                            RuleEntry(
                                id=int(matches.group(1)),
                                match=matches.group(2).strip(),
                                action=matches.group(3).strip(),
                            ),
                        )
            return DNSdistRulesTable(rules=rules, count=len(rules))

        if expected is DNSdistCommandType.COMMANDS_DELTA:
            commands = []
            for command in raw.split("\n"):
                commands.append(DNSdistCommand(command=command))
            return DNSdistCommandsDelta(delta=commands, count=len(commands))

    def _get_all_rules(self) -> DNSdistRulesTable:
        """Get list of all rules."""
        command = "showRules()"
        return self._send_command(
            command,
            expected=DNSdistCommandType.SHOW_RULES,
        )

    def get_rule_by_match(self, match: str) -> RuleEntry | None:
        """Get rule by rule match."""
        rules = self._get_all_rules()
        for rule in rules.rules:
            if rule.match == match:
                return rule

        return None

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
        self._send_command(
            command,
            expected=DNSdistCommandType.GENERIC,
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
        self._send_command(
            command,
            expected=DNSdistCommandType.GENERIC,
        )

        command = """
            addAction(
                AllRule(),
                PoolAction("recursor")
            )
        """
        self._send_command(
            command,
            expected=DNSdistCommandType.GENERIC,
        )

    def add_zone_rule(self, domain: str) -> None:
        """Add rule to redirect master zone DNS requests to auth server."""
        command = f"""
            addAction(
                QNameRule("*.{domain}"),
                PoolAction("master")
            )
        """
        self._send_command(
            command,
            expected=DNSdistCommandType.GENERIC,
        )

        command = f"""
            addAction(
                QNameRule("{domain}"),
                PoolAction("master")
            )
        """
        self._send_command(
            command,
            expected=DNSdistCommandType.GENERIC,
        )

        self._deprioritize_all_match_rule()

        self._persist_config()

    def remove_zone_rule(self, domain: str) -> None:
        """Remove redirect rule from dnsdist."""
        rule_matches = [
            f"qname=={domain}",
            f"qname==*.{domain}",
        ]
        for rule_match in rule_matches:
            rules = self._get_all_rules()
            if not rules.count:
                DNSdistError(
                    "Failed to delete existing rule in dnsdist: Not Found",
                )

            for rule in rules.rules:
                if rule.match == rule_match:
                    command = f"rmRule({rule.id})"
                    self._send_command(
                        command,
                        expected=DNSdistCommandType.GENERIC,
                    )

        self._persist_config()

    def _deprioritize_all_match_rule(self) -> None:
        """Remove and add all matching rule to depriortitize it."""
        rule = self.get_rule_by_match("All")
        if rule is not None:
            command = f"rmRule({rule.id})"
            self._send_command(
                command,
                expected=DNSdistCommandType.GENERIC,
            )

        command = """
            addAction(
                AllRule(),
                PoolAction("recursor")
            )
        """
        self._send_command(
            command,
            expected=DNSdistCommandType.GENERIC,
        )

        self._persist_config()

    def _get_commands_delta(self) -> DNSdistCommandsDelta:
        """Get list of commands that have not been persisted yet."""
        command = "delta()"
        return self._send_command(
            command,
            expected=DNSdistCommandType.COMMANDS_DELTA,
        )

    def _save_commands_delta(
        self,
        commands_delta: DNSdistCommandsDelta,
    ) -> None:
        """Save commands delta to dnsdist config file."""
        with open(self._config_path, "a+", encoding="utf-8") as config_file:
            for command in commands_delta.delta:
                config_file.write(f"{command.command}\n")

    def _clear_console_history(self) -> None:
        """Clear console history to delete written delta."""
        command = "clearConsoleHistory()"
        self._send_command(
            command,
            expected=DNSdistCommandType.GENERIC,
        )

    def _persist_config(self) -> None:
        """Persist dnsdist config to file."""
        commands_delta = self._get_commands_delta()
        if commands_delta.count:
            self._save_commands_delta(commands_delta)

        self._clear_console_history()
