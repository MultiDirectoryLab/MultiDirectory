"""API for managing Bind9 DNS server.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import logging
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, ClassVar

import dns
import dns.zone
import jinja2
from fastapi import APIRouter, Depends, FastAPI
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)

TEMPLATES: ClassVar[jinja2.Environment] = jinja2.Environment(
    loader=jinja2.FileSystemLoader("templates/"),
    autoescape=True,
    keep_trailing_newline=True,
)

ZONE_FILES_DIR = "/opt"
NAMED_LOCAL = "/etc/bind/named.conf.local"
NAMED_OPTIONS = "/etc/bind/named.conf.options"

FIRST_SETUP_RECORDS = [
    {"name": "_ldap._tcp.", "value": "0 0 389 ", "type": "SRV"},
    {"name": "_ldaps._tcp.", "value": "0 0 636 ", "type": "SRV"},
    {"name": "_kerberos._tcp.", "value": "0 0 88 ", "type": "SRV"},
    {"name": "_kerberos._udp.", "value": "0 0 88 ", "type": "SRV"},
    {"name": "_kdc._tcp.", "value": "0 0 88 ", "type": "SRV"},
    {"name": "_kdc._udp.", "value": "0 0 88 ", "type": "SRV"},
    {"name": "_kpasswd._tcp.", "value": "0 0 464 ", "type": "SRV"},
    {"name": "_kpasswd._udp.", "value": "0 0 464 ", "type": "SRV"},
]


class DNSZoneType(StrEnum):
    """DNS zone types."""

    MASTER = "master"
    FORWARD = "forward"


class DNSRecordType(StrEnum):
    """DNS record types."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    PTR = "PTR"
    SRV = "SRV"


@dataclass
class DNSRecord:
    """Single DNS record."""

    name: str
    value: str
    ttl: int


@dataclass
class DNSRecords:
    """List of DNS records grouped by type."""

    type: DNSRecordType
    records: list[DNSRecord]


@dataclass
class DNSZone:
    """DNS zone."""

    name: str
    type: DNSZoneType
    records: list[DNSRecords]


@dataclass
class DNSForwardZone:
    """DNS forward zone."""

    name: str
    type: DNSZoneType
    forwarders: list[str]


class DNSZoneParamName(StrEnum):
    """Possible DNS zone option names."""

    acl = "acl"
    forwarders = "forwarders"
    ttl = "ttl"


class DNSServerParamName(StrEnum):
    """Possible DNS server option names."""

    dnssec = "dnssec-validation"


@dataclass
class DNSZoneParam:
    """DNS zone parameter."""

    name: DNSZoneParamName
    value: str | list[str] | None


class DNSZoneCreateRequest(BaseModel):
    """DNS zone create request scheme."""

    zone_name: str
    zone_type: DNSZoneType
    nameserver: str | None
    params: list[DNSZoneParam]


class DNSZoneUpdateRequest(BaseModel):
    """DNS zone update request scheme."""

    zone_name: str
    params: list[DNSZoneParam]


class DNSZoneDeleteRequest(BaseModel):
    """DNS zone delete request scheme."""

    zone_name: str


class DNSRecordCreateRequest(BaseModel):
    """DNS record create request scheme."""

    zone_name: str
    record_name: str
    record_value: str
    record_type: str
    ttl: int


class DNSRecordUpdateRequest(BaseModel):
    """DNS record update request scheme."""

    zone_name: str
    record_name: str
    record_value: str
    record_type: DNSRecordType
    ttl: int


class DNSRecordDeleteRequest(BaseModel):
    """DNS record delete request schem."""

    zone_name: str
    record_name: str
    record_value: str
    record_type: DNSRecordType


class DNSServerSetupRequest(BaseModel):
    """DNS server setup request schem."""

    zone_name: str


@dataclass
class DNSServerParam:
    """DNS zone parameter."""

    name: DNSServerParamName
    value: str | list[str]


class BindDNSServerManager:
    """Bind9 DNS server manager."""

    @staticmethod
    def _get_zone_obj_by_zone_name(zone_name) -> dns.zone.Zone:
        """Get DNS zone object by zone name.

        Algorithm:
            1. Build the path to the zone file using the zone name.
            2. Load the zone object using dns.zone.from_file.

        Args:
            zone_name (str): Name of the DNS zone.

        Returns:
            dns.zone.Zone: Zone object.

        """
        zone_file = os.path.join(ZONE_FILES_DIR, f"{zone_name}.zone")
        return dns.zone.from_file(
            zone_file,
            relativize=False,
            origin=zone_name,
        )

    def _write_zone_data_to_file(
        self,
        zone_name: str,
        zone: dns.zone.Zone,
    ) -> None:
        """Write zone data to file and reload the zone.

        Algorithm:
            1. Save the zone object to a file.
            2. Call reload to apply changes.

        Args:
            zone_name (str): Name of the DNS zone.
            zone (dns.zone.Zone): Zone object.

        """
        zone.to_file(os.path.join(ZONE_FILES_DIR, f"{zone_name}.zone"))
        self.reload(zone_name)

    def _get_base_domain(self) -> str:
        """Get base domain.

        Algorithm:
            1. Open named.conf.local.
            2. Get first domain.

        """
        named_local = None

        with open(NAMED_LOCAL) as file:
            named_local = file.read()

        pattern = r"""
            zone\s+"([^"]+)"\s*{[^}]*?
            type\s+master\b[^}]*?
        """

        matches = re.search(pattern, named_local, re.DOTALL | re.VERBOSE)

        return matches.group(1)

    def add_zone(
        self,
        zone_name: str,
        zone_type: str,
        nameserver_ip: str | None,
        params: list[DNSZoneParam],
    ) -> None:
        """Add a new DNS zone.

        Algorithm:
            1. Build a dictionary of zone parameters.
            2. Render the zone file and zone options templates.
            3. Process parameters (acl, forwarders, ttl, etc.) and add them
            to the zone options.
            4. Write the zone options to named.conf.local.
            5. Restart the server.

        Args:
            zone_name (str): Name of the DNS zone.
            zone_type (str): Type of the DNS zone.
            nameserver_ip (str | None): Nameserver IP address.
            params (list[DNSZoneParam]): List of zone parameters.

        """
        params_dict = {param.name: param.value for param in params}

        if zone_type != DNSZoneType.FORWARD:
            nameserver_ip = (
                nameserver_ip
                if nameserver_ip is not None
                else os.getenv("DEFAULT_NAMESERVER")
            )
            nameserver = (
                self._get_base_domain()
                if "in-addr.arpa" in zone_name
                else zone_name
            )

            zf_template = TEMPLATES.get_template("zone.template")
            zone_file = zf_template.render(
                domain=zone_name,
                nameserver=nameserver,
                ttl=params_dict.get("ttl", 604800),
            )
            with open(
                os.path.join(ZONE_FILES_DIR, f"{zone_name}.zone"),
                "w",
            ) as file:
                file.write(zone_file)

            if "in-addr.arpa" not in zone_name:
                for record in [
                    DNSRecord(
                        name=zone_name,
                        value=nameserver_ip,
                        ttl=604800,
                    ),
                    DNSRecord(
                        name=f"ns1.{zone_name}",
                        value=nameserver_ip,
                        ttl=604800,
                    ),
                    DNSRecord(
                        name=f"ns2.{zone_name}",
                        value="127.0.0.1",
                        ttl=604800,
                    ),
                ]:
                    self.add_record(
                        record,
                        DNSRecordType.A,
                        zone_name=zone_name,
                    )

        zo_template = TEMPLATES.get_template("zone_options.template")
        zone_options = zo_template.render(
            zone_name=zone_name,
            zone_type=zone_type,
            forwarders=params_dict.get("forwarders"),
        )

        for param in params:
            param_name = param.name if param.name != "acl" else "allow-query"
            if (
                param_name == "allow-query"
                and zone_type == DNSZoneType.FORWARD
            ):
                continue
            if isinstance(param.value, list):
                param_value = "{ " + f"{'; '.join(param.value)};" + " }"
            else:
                param_value = param.value

            zone_options = self._add_zone_param(
                zone_options,
                zone_name,
                param_name,
                param_value,
            )

        with open(NAMED_LOCAL, "a") as file:
            file.write(zone_options)

        self.restart()

    @staticmethod
    def _add_zone_param(
        named_local: str,
        zone_name: str,
        param_name: str,
        param_value: str,
    ) -> str:
        """Add a zone parameter to named.conf.local.

        Regex explanation:
            - (zone\\s+"{zone_name}"\\s*{{[^}}]*?)
                Captures the start of the zone block for the given zone_name,
                including all content up to the closing '};'.
            - (\\s*}};)
                Captures the closing of the zone block
                (with optional whitespace).
                The regex is used to insert a new parameter
                just before the end of the zone block.

        Algorithm:
            1. Use re.sub to add the parameter line inside the zone block.
            2. Return the modified text.

        Args:
            named_local (str): Contents of named.conf.local.
            zone_name (str): Name of the DNS zone.
            param_name (str): Parameter name.
            param_value (str): Parameter value.

        Returns:
            str: Modified named.conf.local content.

        """
        pattern = rf'(zone\s+"{re.escape(zone_name)}"\s*{{[^}}]*?)(\s*}};)'
        replacement = rf"\1\n    {param_name} {param_value};\2"
        return re.sub(pattern, replacement, named_local, flags=re.DOTALL)

    @staticmethod
    def _delete_zone_param(
        named_local: str,
        zone_name: str,
        param_name: str,
    ) -> str:
        """Delete a zone parameter from named.conf.local.

        Regex explanation:
            - (zone\\s+"{zone_name}"\\s*{{)
                Captures the start of the zone block for the given zone_name.
            - (.*?)
                Non-greedy match for any content up to the parameter line.
            - (^\\s*{param_name}\\s+(?:[^{{;\\n}}]+|{{[^}}]+}})\\s*;\\s*\\n)
                Matches the parameter line (with possible value in braces
                or not), including the trailing semicolon and newline.
            - (.*?}})
                Matches the rest of the zone block up to the closing brace.
            The regex is used to remove the parameter line from the zone block.

        Algorithm:
            1. Use re.sub to remove the parameter line from the zone block.
            2. Return the modified text.

        Args:
            named_local (str): Contents of named.conf.local.
            zone_name (str): Name of the DNS zone.
            param_name (str): Parameter name.

        Returns:
            str: Modified named.conf.local content.

        """
        pattern = rf"""
        (zone\s+"{re.escape(zone_name)}"\s*{{)
        (.*?)
        ^\s*{re.escape(param_name)}\s+
        (?:[^{{;\n}}]+|{{[^}}]+}})
        \s*;\s*\n
        (.*?}})
        """

        return re.sub(
            pattern,
            r"\1\2\3",
            named_local,
            flags=re.DOTALL | re.VERBOSE | re.MULTILINE,
        )

    def _update_zone_param(
        self,
        named_local: str,
        zone_name: str,
        param_name: str,
        param_value: str,
    ) -> str:
        """Update a zone parameter in named.conf.local.

        Algorithm:
            1. Remove the old parameter value using _delete_zone_param.
            2. Add the new value using _add_zone_param.
            3. Return the modified text.

        Args:
            named_local (str): Contents of named.conf.local.
            zone_name (str): Name of the DNS zone.
            param_name (str): Parameter name.
            param_value (str): Parameter value.

        Returns:
            str: Modified named.conf.local content.

        """
        new_named_local = self._delete_zone_param(
            named_local,
            zone_name,
            param_name,
        )
        return self._add_zone_param(
            new_named_local,
            zone_name,
            param_name,
            param_value,
        )

    def update_zone(self, zone_name: str, params: list[DNSZoneParam]) -> None:
        """Update zone parameters.

        Regex explanation:
            - ^zone\\s+"{zone_name}"\\s*{{
                Matches the start of the zone block for the given zone_name.
            - [^}}]*?
                Non-greedy match for any content inside the block up
                to the parameter.
            - \\s{param_name}\\b
                Matches the parameter name as a whole word.
            - \\s+(?:[^{{;\\n}}]+|{{[^}}]+}})\\s*;
                Matches the parameter value (either a simple value or a block
                in braces), followed by a semicolon.
            This regex is used to check if the parameter exists in the zone
            block.

        Algorithm:
            1. Read named.conf.local content.
            2. For each parameter, check if it exists in the zone block
            using regex.
            3. If value is None, remove the parameter; otherwise, update or
            add it.
            4. Write the modified config back to the file.

        Args:
            zone_name (str): Name of the DNS zone.
            params (list[DNSZoneParam]): List of zone parameters.

        """
        named_local = None
        with open(NAMED_LOCAL) as file:
            named_local = file.read()

        for param in params:
            param_name = param.name if param.name != "acl" else "allow-query"
            pattern = rf"""
            ^zone\s+"{re.escape(zone_name)}"\s*{{
            [^}}]*?
            \s{re.escape(param_name)}\b
            \s+(?:[^{{;\n}}]+|{{[^}}]+}})
            \s*;
            """
            has_param = bool(
                re.search(
                    pattern,
                    named_local,
                    flags=re.MULTILINE | re.VERBOSE | re.DOTALL,
                ),
            )

            if param.value is None:
                named_local = self._delete_zone_param(
                    named_local,
                    zone_name,
                    param_name,
                )
                continue

            if isinstance(param.value, list):
                param_value = "{ " + f"{'; '.join(param.value)};" + " }"
            else:
                param_value = param.value

            if has_param:
                named_local = self._update_zone_param(
                    named_local,
                    zone_name,
                    param_name,
                    param_value,
                )
            else:
                named_local = self._add_zone_param(
                    named_local,
                    zone_name,
                    param_name,
                    param_value,
                )

        with open(NAMED_LOCAL, "w") as file:
            file.write(named_local)

    def delete_zone(self, zone_name: str) -> None:
        """Delete an existing zone.

        Regex explanation:
            - ^\\s*zone\\s+"{zone_name}"\\s*{{
                Matches the start of the zone block for the given zone_name.
            - (?:[^{{}}]|{{(?:[^{{}}]|{{[^}}]*}})*}})*?
                Non-greedy match for any content inside the block, including
                nested braces.
            - \\s*}};\\s*
                Matches the closing of the zone block (with optional
                whitespace).
            This regex is used to remove the entire zone block from the config.

        Algorithm:
            1. Read named.conf.local content.
            2. Determine the zone type.
            3. Remove the zone block using regex.
            4. If not a forward zone, remove the zone file.
            5. Restart the server.

        Args:
            zone_name (str): Name of the DNS zone.

        """
        named_local = None
        with open(NAMED_LOCAL) as file:
            named_local = file.read()

        zone_type = self.get_zone_type_by_zone_name(zone_name)

        pattern = rf"""
            ^\s*zone\s+"{re.escape(zone_name)}"\s*{{
            (?:
                [^{{}}]
                |
                {{(?:[^{{}}]|{{[^}}]*}})*}}
            )*?
            \s*}};\s*
        """
        named_local = re.sub(
            pattern,
            "",
            named_local,
            flags=re.MULTILINE | re.VERBOSE | re.DOTALL,
        )
        with open(NAMED_LOCAL, "w") as file:
            file.write(named_local)

        if zone_type != DNSZoneType.FORWARD:
            os.remove(os.path.join(ZONE_FILES_DIR, f"{zone_name}.zone"))

        self.restart()

    def reload(self, zone_name: str | None = None) -> None:
        """Reload a zone by name or all zones if no name is provided.

        Algorithm:
            1. Call rndc reload with the zone name or without it.

        Args:
            zone_name (str | None): Name of the DNS zone or None.

        """
        subprocess.run(  # noqa: S603
            [
                "/usr/sbin/rndc",
                "reload",
                zone_name if zone_name else "",
            ],
        )

    def restart(self) -> None:
        """Restart the Bind9 server (reconfig).

        Algorithm:
            1. Call rndc reconfig.
        """
        subprocess.run(  # noqa: S603
            [
                "/usr/sbin/rndc",
                "reconfig",
            ],
        )

    def first_setup(self, zone_name: str) -> str:
        """Perform initial setup of the Bind9 server.

        Algorithm:
            1. Create a master zone.
            2. Add standard SRV records for services (ldap, kerberos, etc.).

        Args:
            zone_name (str): Name of the DNS zone.

        """
        self.add_zone(
            zone_name,
            "master",
            None,
            params=[],
        )
        for record in FIRST_SETUP_RECORDS:
            self.add_record(
                DNSRecord(
                    name=record.get("name") + zone_name,
                    value=record.get("value") + zone_name,
                    ttl=604800,
                ),
                record.get("type"),
                zone_name,
            )

    @staticmethod
    def get_zone_type_by_zone_name(zone_name: str) -> DNSZoneType:
        """Get the zone type by zone name.

        Regex explanation:
            - zone\\s+"{zone_name}"\\s*{{\\s*type\\s*([^;]+);
                Matches the zone block for the given zone_name and captures
                the type value after 'type'.
            The first capturing group contains the zone type
            (e.g., master, forward).

        Algorithm:
            1. Read named.conf.local content.
            2. Use regex to find the zone block and extract the type.

        Args:
            zone_name (str): Name of the DNS zone.

        Returns:
            DNSZoneType: Zone type.

        """
        with open(NAMED_LOCAL) as file:
            named_local_settings = file.read()

        pattern = rf'zone\s*"{re.escape(zone_name)}"\s*{{\s*type\s*([^;]+);'
        zone_type_match = re.search(pattern, named_local_settings)
        return zone_type_match.group(1).strip()

    def get_all_records_from_zone(
        self,
        zone_name: str,
    ) -> DNSRecords:
        """Get all records from a zone by name.

        Algorithm:
            1. Load the zone object.
            2. Iterate over all rdata and group by type.
            3. Return a list of DNSRecords by type.

        Args:
            zone_name (str): Name of the DNS zone.

        Returns:
            list[DNSRecords]: List of DNSRecords grouped by type.

        """
        result: defaultdict[str, list] = defaultdict(list)

        zone = self._get_zone_obj_by_zone_name(zone_name)
        for name, ttl, rdata in zone.iterate_rdatas():
            record_type = rdata.rdtype.name

            result[record_type].append(
                DNSRecord(
                    name=name.to_text(),
                    value=rdata.to_text(),
                    ttl=ttl,
                ),
            )

        return [
            DNSRecords(type=record_type, records=records)
            for record_type, records in result.items()
        ]

    def get_all_records(self) -> list[DNSZone]:
        """Get all records from all zones.

        Algorithm:
            1. Scan the directory for zone files.
            2. For each file, determine the zone name and type.
            3. Get all records for the zone.
            4. Return a list of DNSZone objects.

        Returns:
            list[DNSZone]: List of DNSZone objects.

        """
        zone_files = os.listdir(ZONE_FILES_DIR)

        result: list[DNSZone] = []
        for file in zone_files:
            if file.split(".")[-1] != "zone":
                continue
            zone_name = ".".join(file.split(".")[:-1])
            zone_type = self.get_zone_type_by_zone_name(zone_name)
            zone_records = self.get_all_records_from_zone(
                zone_name,
            )
            result.append(
                DNSZone(
                    name=zone_name,
                    type=zone_type,
                    records=zone_records,
                ),
            )

        return result

    async def get_forward_zones(self) -> list[DNSForwardZone]:
        """Get all forward DNS zones.

        Regex explanation:
            - zone\\s+"([^"]+)"\\s*{{
                Captures the zone name.
            - [^}}]*?type\\s+forward\\b[^}}]*?
                Matches content up to the 'type forward' declaration.
            - forwarders\\s*{{([^}}]+)}}
                Captures the content inside the forwarders block
                (list of forwarder IPs).
            The first group is the zone name,
            the second group is the forwarders list.

        Algorithm:
            1. Read named.conf.local content.
            2. Use regex to find forward zone blocks and their forwarders.
            3. Return a list of DNSForwardZone objects.

        Returns:
            list[DNSForwardZone]: List of forward zones.

        """
        named_local = None
        with open(NAMED_LOCAL) as file:
            named_local = file.read()

        pattern = r"""
            zone\s+"([^"]+)"\s*{[^}]*?
            type\s+forward\b[^}]*?
            forwarders\s*{([^}]+)}
        """

        matches = re.findall(pattern, named_local, re.DOTALL | re.VERBOSE)

        result = []
        for zone_name, forwarders in matches:
            clean_forwarders = [
                forwarder.strip()
                for forwarder in forwarders.split(";")
                if forwarder.strip()
            ]
            result.append(
                DNSForwardZone(
                    zone_name,
                    DNSZoneType.FORWARD,
                    clean_forwarders,
                ),
            )

        return result

    def add_record(
        self,
        record: DNSRecord,
        record_type: DNSRecordType,
        zone_name: str,
    ) -> None:
        """Add a DNS record to a zone.

        Algorithm:
            1. Load the zone object.
            2. Build rdata by type and value.
            3. Add rdata to the rdataset.
            4. Save changes to the zone file and reload the zone.

        Args:
            record (DNSRecord): DNS record to add.
            record_type (DNSRecordType): Type of the DNS record.
            zone_name (str): Name of the DNS zone.

        """
        zone = self._get_zone_obj_by_zone_name(zone_name)

        record_name = dns.name.from_text(record.name)
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.from_text(record_type),
            record.value,
        )

        zone.find_rdataset(record_name, rdata.rdtype, create=True).add(
            rdata,
            ttl=record.ttl,
        )

        self._write_zone_data_to_file(zone_name, zone)

    def delete_record(
        self,
        record: DNSRecord,
        record_type: DNSRecordType,
        zone_name: str,
    ) -> None:
        """Delete a record from a zone.

        Algorithm:
            1. Load the zone object.
            2. Find the rdataset by name and type.
            3. If rdata is present, remove it from the rdataset.
            4. Save changes to the zone file and reload the zone.

        Args:
            record (DNSRecord): DNS record to delete.
            record_type (DNSRecordType): Type of the DNS record.
            zone_name (str): Name of the DNS zone.

        """
        zone = self._get_zone_obj_by_zone_name(zone_name)
        name = dns.name.from_text(record.name)
        rdatatype = dns.rdatatype.from_text(record_type)
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            rdatatype,
            record.value,
        )

        if name in zone.nodes:
            node = zone.nodes[name]
            rdataset = node.get_rdataset(dns.rdataclass.IN, rdatatype)
            if rdataset and rdata in rdataset:
                rdataset.remove(rdata)

        self._write_zone_data_to_file(zone_name, zone)

    def update_record(
        self,
        old_record: DNSRecord,
        new_record: DNSRecord,
        record_type,
        zone_name,
    ) -> None:
        """Update a record in a zone (value or TTL).

        Algorithm:
            1. Delete the old record.
            2. Add the new record with updated values.

        Args:
            old_record (DNSRecord): Old DNS record.
            new_record (DNSRecord): New DNS record.
            record_type: Type of the DNS record.
            zone_name (str): Name of the DNS zone.

        """
        self.delete_record(old_record, record_type, zone_name)
        self.add_record(new_record, record_type, zone_name)

    @staticmethod
    def _add_new_server_param(
        named_options: str,
        param_name: str,
        param_value: str,
    ) -> str:
        """Add a new parameter to the options block in named.conf.options.

        Regex explanation:
            - (options\\s*\\{{[\\s\\S]*?)
                Captures the start of the options block and all its content
                up to the closing '};'.
            - (\\s*\\}};)
                Captures the closing of the options block
                (with optional whitespace).
            The regex is used to insert a new parameter just before the end of
            the options block.

        Algorithm:
            1. Use re.sub to add the parameter line inside the options block.
            2. Return the modified text.

        Args:
            named_options (str): Contents of named.conf.options.
            param_name (str): Parameter name.
            param_value (str): Parameter value.

        Returns:
            str: Modified named.conf.options content.

        """
        return re.sub(
            r"(options\s*\{[\s\S]*?)(\s*\};)",
            rf"\1    {param_name} {param_value};\2",
            named_options,
            flags=re.DOTALL,
        )

    def update_dns_settings(self, settings: list[DNSServerParam]) -> None:
        """Update or add DNS server parameters.

        Regex explanation:
            - \\b{param_name}\\s+
                Matches the parameter name as a whole word,
                followed by whitespace.
            - ([^;\\n{{]+|{{[^}}]+}})
                Captures the parameter value, which can be a simple value or
                a block in braces.
            The first capturing group contains the parameter value.

        Algorithm:
            1. Read named.conf.options content.
            2. For each parameter, search for it using regex.
            3. If not found, add it; otherwise, update it.
            4. Write the modified config back to the file.

        Args:
            settings (list[DNSServerParam]): List of server parameters.

        """
        named_options = None

        with open(NAMED_OPTIONS) as file:
            named_options = file.read()

        for param in settings:
            if isinstance(param.value, list):
                param_value = "{ " + f"{'; '.join(param.value)};" + " }"
            else:
                param_value = param.value
            pattern = rf"\b{re.escape(param.name)}\s+([^;\n{{]+|{{[^}}]+}})"
            matched_param = re.search(
                pattern,
                named_options,
                flags=re.MULTILINE,
            )
            if matched_param is None:
                named_options = self._add_new_server_param(
                    named_options,
                    param.name,
                    param_value,
                )
            else:
                named_options = re.sub(
                    pattern,
                    f"{param.name} {param_value}",
                    named_options,
                )

        with open(NAMED_OPTIONS, "w") as file:
            file.write(named_options)

        self.restart()

    @staticmethod
    def get_server_settings() -> list[DNSServerParam]:
        """Get a list of modifiable DNS server settings.

        Regex explanation:
            - \\b{param_name}\\s+
                Matches the parameter name as a whole word,
                followed by whitespace.
            - ([^;\\n{{]+|{{[^}}]+}})
                Captures the parameter value, which can be a simple value or
                a block in braces.
            The first capturing group contains the parameter value.

        Algorithm:
            1. Read named.conf.options content.
            2. For each parameter in DNSServerParamName,
            search for its value using regex.
            3. Return a list of DNSServerParam objects.

        Returns:
            list[DNSServerParam]: List of server parameters.

        """
        named_options = None
        with open(NAMED_OPTIONS) as file:
            named_options = file.read()

        result = []
        for param_name in DNSServerParamName:
            pattern = rf"\b{re.escape(param_name)}\s+([^;\n{{]+|{{[^}}]+}})"
            matched_param_value = re.search(pattern, named_options)
            result.append(
                DNSServerParam(
                    name=param_name,
                    value=matched_param_value.group(1).strip(),
                ),
            )

        return result


async def get_dns_manager() -> type[BindDNSServerManager]:
    """Get DNS server manager client."""
    return BindDNSServerManager()


zone_router = APIRouter(prefix="/zone", tags=["zone"])
record_router = APIRouter(prefix="/record", tags=["record"])
server_router = APIRouter(prefix="/server", tags=["server"])


@zone_router.post("")
def create_zone(
    data: DNSZoneCreateRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Create DNS zone."""
    dns_manager.add_zone(
        data.zone_name,
        data.zone_type,
        data.nameserver,
        data.params,
    )


@zone_router.patch("")
def update_zone(
    data: DNSZoneUpdateRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Update DNS zone settings."""
    dns_manager.update_zone(data.zone_name, data.params)


@zone_router.delete("")
def delete_zone(
    data: DNSZoneDeleteRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Delete DNS zone."""
    dns_manager.delete_zone(data.zone_name)


@zone_router.get("")
async def get_all_records_by_zone(
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> list[DNSZone]:
    """Get all DNS records grouped by zone."""
    return dns_manager.get_all_records()


@zone_router.get("/forward")
async def get_forward_zones(
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> list[DNSForwardZone]:
    """Get all forward DNS zones."""
    return await dns_manager.get_forward_zones()


@record_router.post("")
def create_record(
    data: DNSRecordCreateRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Create DNS record in given zone."""
    dns_manager.add_record(
        DNSRecord(
            data.record_name,
            data.record_value,
            data.ttl,
        ),
        data.record_type,
        data.zone_name,
    )


@record_router.patch("")
async def update_record(
    data: DNSRecordUpdateRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Update existing DNS record."""
    await dns_manager.update_record(
        old_record=DNSRecord(
            data.record_name,
            data.record_value,
            0,
        ),
        new_record=DNSRecord(
            data.record_name,
            data.record_value,
            data.ttl,
        ),
        record_type=data.record_type,
        zone_name=data.zone_name,
    )


@record_router.delete("")
def delete_record(
    data: DNSRecordDeleteRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Delete existing DNS record."""
    dns_manager.delete_record(
        DNSRecord(
            data.record_name,
            data.record_value,
            0,
        ),
        data.record_type,
        data.zone_name,
    )


@server_router.get("/restart")
def restart_dns_server(
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Restart DNS server via reconfig."""
    dns_manager.restart()


@zone_router.get("/reload/{zone_name}")
def reload_zone(
    zone_name: str,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Force reload DNS zone from zone file."""
    dns_manager.reload(zone_name)


@server_router.patch("/settings")
def update_dns_server_settings(
    settings: list[DNSServerParam],
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Update settings of DNS server."""
    dns_manager.update_dns_settings(settings)


@server_router.get("/settings")
async def get_server_settings(
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> list[DNSServerParam]:
    """Get list of modifiable server settings."""
    return dns_manager.get_server_settings()


@server_router.post("/setup")
def setup_server(
    data: DNSServerSetupRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Init setup of DNS server."""
    dns_manager.first_setup(data.zone_name)


def create_app() -> FastAPI:
    """Create FastAPI app."""
    app = FastAPI(
        name="DNSServerManager",
        title="DNSServerManager",
    )

    app.include_router(record_router)
    app.include_router(zone_router)
    app.include_router(server_router)
    return app
