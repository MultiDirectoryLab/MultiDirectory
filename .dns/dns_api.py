"""API for managing Bind9 DNS server.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
import logging
import os
import re
from abc import ABC, abstractmethod
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
    enable_async=True,
    autoescape=True,
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

    record_name: str
    record_value: str
    ttl: int


@dataclass
class DNSRecords:
    """List of DNS records grouped by type."""

    record_type: DNSRecordType
    records: list[DNSRecord]


@dataclass
class DNSZone:
    """DNS zone."""

    zone_name: str
    zone_type: DNSZoneType
    records: list[DNSRecords]


@dataclass
class DNSForwardZone:
    """DNS forward zone."""

    zone_name: str
    zone_type: DNSZoneType
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


class AbstractDNSServerManager(ABC):
    """DNS server manager."""

    @abstractmethod
    async def add_zone(
        self,
        zone_name: str,
        zone_type: str,
        params: list[DNSZoneParam],
    ) -> None:
        """Add new zone.

        :param str name: zone name
        :param str zone_settings: zone settings of the new zone.
        """

    @abstractmethod
    async def update_zone(self, name: str, params: list[DNSZoneParam]) -> None:
        """Update zone settings.

        :param str name: zone name
        :param list params: list of new zone params.
        """

    @abstractmethod
    async def delete_zone(self, name: str) -> None:
        """Delete existing zone.

        :param str name: zone name.
        """

    @abstractmethod
    async def reload(self, zone: str | None = None) -> None:
        """Reload zone with given name or all zones if none provided.

        :param str | None name: zone name.
        """

    @abstractmethod
    async def restart(self) -> None:
        """Restart Bind9 server."""


class BindDNSServerManager(AbstractDNSServerManager):
    """Bind9 DNS server manager."""

    def __init__(self, loop: asyncio.AbstractEventLoop | None = None):
        """Initialize Bind9 DNS server manager."""
        self.loop = loop or asyncio.get_running_loop()

    @staticmethod
    def _get_zone_obj_by_zone_name(zone_name) -> dns.zone.Zone:
        zone_file = os.path.join(ZONE_FILES_DIR, f"{zone_name}.zone")
        return dns.zone.from_file(
            zone_file, relativize=False, origin=zone_name
        )

    async def _write_zone_data_to_file(
        self, zone_name: str, zone: dns.zone.Zone
    ) -> None:
        zone.to_file(os.path.join(ZONE_FILES_DIR, f"{zone_name}.zone"))
        await self.reload(zone_name)

    async def add_zone(
        self,
        zone_name: str,
        zone_type: str,
        nameserver: str | None,
        params: list[DNSZoneParam],
    ) -> None:
        params_dict = {param.name: param.value for param in params}
        """Add new zone."""
        zf_template = TEMPLATES.get_template("zone.template")
        nameserver_ip = (
            nameserver
            if nameserver is not None
            else os.getenv("DEFAULT_NAMESERVER")
        )
        zone_file = await zf_template.render_async(
            domain=zone_name,
            nameserver_ip=nameserver_ip,
            ttl=params_dict.get("ttl", 604800),
        )
        with open(
            os.path.join(ZONE_FILES_DIR, f"{zone_name}.zone"),
            "w",
        ) as file:
            file.write(zone_file)

        zo_template = TEMPLATES.get_template("zone_options.template")
        zone_options = await zo_template.render_async(
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
                zone_options, zone_name, param_name, param_value
            )

        with open(NAMED_LOCAL, "a") as file:
            file.write(zone_options)

        await self.reload(zone_name)

    @staticmethod
    def _add_zone_param(
        named_local: str, zone_name: str, param_name: str, param_value: str
    ) -> str:
        pattern = rf'(zone\s+"{re.escape(zone_name)}"\s*{{[^}}]*?)(\s*}};)'
        replacement = rf"\1\n    {param_name} {param_value};\2"
        return re.sub(pattern, replacement, named_local, flags=re.DOTALL)

    @staticmethod
    def _delete_zone_param(
        named_local: str,
        zone_name: str,
        param_name: str,
    ) -> str:
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
        new_named_local = self._delete_zone_param(
            named_local, zone_name, param_name
        )
        return self._add_zone_param(
            new_named_local, zone_name, param_name, param_value
        )

    def update_zone(self, zone_name: str, params: list[DNSZoneParam]) -> None:
        """Update zone settings."""
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
                )
            )

            if param.value is None:
                named_local = self._delete_zone_param(
                    named_local, zone_name, param_name
                )
                continue

            if isinstance(param.value, list):
                param_value = "{ " + f"{'; '.join(param.value)};" + " }"
            else:
                param_value = param.value

            if has_param:
                named_local = self._update_zone_param(
                    named_local, zone_name, param_name, param_value
                )
            else:
                named_local = self._add_zone_param(
                    named_local, zone_name, param_name, param_value
                )

        with open(NAMED_LOCAL, "w") as file:
            file.write(named_local)

    async def delete_zone(self, zone_name: str) -> None:
        """Delete existing zone."""
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

        await self.restart()

    async def reload(self, zone_name: str | None = None) -> None:
        """Reload zone with given name or all zones if none provided."""
        await asyncio.create_subprocess_exec(
            "rndc",
            "reload",
            zone_name if zone_name else "",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def restart(self) -> None:
        """Force Bind9 server to read config files again to apply changes."""
        await asyncio.create_subprocess_exec(
            "rndc",
            "reconfig",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def first_setup(self, zone_name: str) -> str:
        """Perform first setup of Bind9 server."""
        await self.add_zone(
            zone_name,
            "master",
            params=[],
        )
        for record in FIRST_SETUP_RECORDS:
            await self.add_record(
                DNSRecord(
                    record_name=record.get("name") + zone_name,
                    record_value=record.get("value") + zone_name,
                    ttl=604800,
                ),
                record.get("type"),
                zone_name,
            )

    @staticmethod
    def get_zone_type_by_zone_name(zone_name: str) -> DNSZoneType:
        with open(NAMED_LOCAL) as file:
            named_local_settings = file.read()

        pattern = rf'zone\s*"{re.escape(zone_name)}"\s*{{\s*type\s*([^;]+);'
        zone_type_match = re.search(pattern, named_local_settings)
        return zone_type_match.group(1).strip()

    def get_all_records_from_zone(
        self,
        zone_name: str,
    ) -> DNSRecords:
        """Get all records by given zone name."""
        result: defaultdict[str, list] = defaultdict(list)

        zone = self._get_zone_obj_by_zone_name(zone_name)
        for name, ttl, rdata in zone.iterate_rdatas():
            record_type = rdata.rdtype.name

            result[record_type].append(
                DNSRecord(
                    record_name=name.to_text(),
                    record_value=rdata.to_text(),
                    ttl=ttl,
                )
            )

        return [
            DNSRecords(record_type=record_type, records=records)
            for record_type, records in result.items()
        ]

    def get_all_records(self) -> list[DNSZone]:
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
                    zone_name=zone_name,
                    zone_type=zone_type,
                    records=zone_records,
                )
            )

        return result

    async def get_forward_zones(self) -> list[DNSForwardZone]:
        """Get all forward DNS zones."""
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
                )
            )

        return result

    async def add_record(
        self,
        record: DNSRecord,
        record_type: DNSRecordType,
        zone_name: str,
    ) -> None:
        """Add DNS record to given zone."""
        zone = self._get_zone_obj_by_zone_name(zone_name)

        record_name = dns.name.from_text(record.record_name)
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.from_text(record_type),
            record.record_value,
        )

        zone.find_rdataset(record_name, rdata.rdtype, create=True).add(
            rdata, ttl=record.ttl
        )

        await self._write_zone_data_to_file(zone_name, zone)

    async def delete_record(
        self,
        record: DNSRecord,
        record_type: DNSRecordType,
        zone_name: str,
    ) -> None:
        """Delete specific record from given DNS zone."""
        zone = self._get_zone_obj_by_zone_name(zone_name)
        name = dns.name.from_text(record.record_name)
        rdatatype = dns.rdatatype.from_text(record_type)
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN, rdatatype, record.record_value
        )

        if name in zone.nodes:
            node = zone.nodes[name]
            rdataset = node.get_rdataset(dns.rdataclass.IN, rdatatype)
            if rdataset and rdata in rdataset:
                rdataset.remove(rdata)

        await self._write_zone_data_to_file(zone_name, zone)

    def update_record(
        self,
        old_record: DNSRecord,
        new_record: DNSRecord,
        record_type,
        zone_name,
    ) -> None:
        """Update specific record from given DNS zone.

        Only changing record value or ttl considered as record update.
        """
        self.delete_record(old_record, record_type, zone_name)
        self.add_record(new_record, record_type, zone_name)

    @staticmethod
    def _add_new_server_param(
        named_options: str,
        param_name: str,
        param_value: str,
    ) -> str:
        return re.sub(
            r"(options\s*\{[\s\S]*?)(\s*\};)",
            rf"\1    {param_name} {param_value};\2",
            named_options,
            flags=re.DOTALL,
        )

    def update_dns_settings(self, settings: list[DNSServerParam]) -> None:
        """Update given DNS server params or create if not present."""
        named_options = None

        with open(NAMED_OPTIONS) as file:
            named_options = file.read()

        for param in settings:
            if isinstance(param.value, list):
                param_value = "{ " + f"{'; '.join(param.value)};" + " }"
            else:
                param_value = param.value
            pattern = rf"^\s*{re.escape(param.name)}\s+"
            matched_param = re.search(
                pattern, named_options, flags=re.MULTILINE
            )
            if matched_param is None:
                named_options = self._add_new_server_param(
                    named_options,
                    param.name,
                    param_value,
                )
            else:
                re.sub(
                    pattern,
                    f"{param.name} {'yes' if param.value is True else 'no'}",
                    named_options,
                )

        with open(NAMED_OPTIONS, "w") as file:
            file.write(named_options)

    @staticmethod
    def get_server_settings() -> list[DNSServerParam]:
        """Get list of modifiable DNS server settings."""
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


async def get_dns_manager() -> type[AbstractDNSServerManager]:
    """Get DNS server manager client."""
    return BindDNSServerManager()


zone_router = APIRouter(prefix="/zone", tags=["zone"])
record_router = APIRouter(prefix="/record", tags=["record"])
server_router = APIRouter(prefix="/server", tags=["server"])


@zone_router.post("")
async def create_zone(
    data: DNSZoneCreateRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Create DNS zone."""
    await dns_manager.add_zone(
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
async def delete_zone(
    data: DNSZoneDeleteRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Delete DNS zone."""
    await dns_manager.delete_zone(data.zone_name)


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
async def create_record(
    data: DNSRecordCreateRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Create DNS record in given zone."""
    await dns_manager.add_record(
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
async def delete_record(
    data: DNSRecordDeleteRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Delete existing DNS record."""
    await dns_manager.delete_record(
        DNSRecord(
            data.record_name,
            data.record_value,
            0,
        ),
        data.record_type,
        data.zone_name,
    )


@server_router.get("/restart")
async def restart_dns_server(
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Restart DNS server via reconfig."""
    await dns_manager.restart()


@zone_router.get("/reload/{zone_name}")
async def reload_zone(
    zone_name: str,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Force reload DNS zone from zone file."""
    await dns_manager.reload(zone_name)


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
async def setup_server(
    data: DNSServerSetupRequest,
    dns_manager: Annotated[BindDNSServerManager, Depends(get_dns_manager)],
) -> None:
    """Init setup of DNS server."""
    await dns_manager.first_setup(data.zone_name)


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
