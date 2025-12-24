"""Schemas for main router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import final

from dishka import AsyncContainer
from pydantic import BaseModel, Field, PrivateAttr, SecretStr
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression

from entities import Directory
from ldap_protocol.dns.enums import DNSManagerState, DNSRecordType
from ldap_protocol.filter_interpreter import (
    Filter,
    FilterInterpreterProtocol,
    StringFilterInterpreter,
)
from ldap_protocol.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap_protocol.ldap_responses import SearchResultDone, SearchResultEntry
from ldap_protocol.utils.const import GRANT_DN_STRING


class SearchRequest(LDAPSearchRequest):
    """Search request for web api."""

    filter: str = Field(..., examples=["(objectClass=*)"])  # type: ignore

    _filter_interpreter: FilterInterpreterProtocol = PrivateAttr(
        default_factory=StringFilterInterpreter,
    )

    def _cast_filter(self) -> UnaryExpression | ColumnElement:
        """Cast str filter to sa sql."""
        filter_ = self.filter.lower().replace("objectcategory", "objectclass")
        return self._filter_interpreter.cast_to_sql(
            Filter.parse(filter_).simplify(),
        )

    @staticmethod
    def get_directory_sid(directory: Directory) -> str:  # type: ignore
        return directory.object_sid

    @staticmethod
    def get_directory_guid(directory: Directory) -> str:  # type: ignore
        return str(directory.object_guid)

    @final
    async def handle_api(  # type: ignore
        self,
        container: AsyncContainer,
    ) -> list[SearchResultEntry | SearchResultDone]:
        """Get all responses."""
        return await self._handle_api(container)  # type: ignore


class SearchResponse(SearchResultDone):
    """Search response for web api."""

    search_result: list[SearchResultEntry]


class KerberosSetupRequest(BaseModel):
    """Kerberos setup data."""

    krbadmin_password: SecretStr
    admin_password: SecretStr
    stash_password: SecretStr


class DNSServiceSetStateRequest(BaseModel):
    """DNS set state request schema."""

    state: DNSManagerState


class DNSServiceSetupRequest(BaseModel):
    """DNS setup request schema."""

    domain: str
    dns_ip_address: IPv4Address | IPv6Address | None = None
    tsig_key: str | None = None


class DNSServiceRecordBaseRequest(BaseModel):
    """DNS setup base schema."""

    record_name: str
    record_type: DNSRecordType


class DNSServiceRecordCreateRequest(DNSServiceRecordBaseRequest):
    """DNS create request schema."""

    record_value: str
    ttl: int | None = None


class DNSServiceRecordDeleteRequest(DNSServiceRecordBaseRequest):
    """DNS delete request schema."""

    record_value: str


class DNSServiceRecordUpdateRequest(DNSServiceRecordBaseRequest):
    """DNS update request schema."""

    record_value: str
    ttl: int | None = None


class DNSServiceForwardZoneRequest(BaseModel):
    """DNS zone create request scheme."""

    zone_name: str
    servers: list[str]


class DNSServiceMasterZoneRequest(BaseModel):
    """DNS zone create request scheme."""

    zone_name: str
    nameserver_ip: str
    dnssec: bool = False


class DNSServiceZoneDeleteRequest(BaseModel):
    """DNS zone delete request scheme."""

    zone_ids: list[str]


class DNSServiceForwardZoneCheckRequest(BaseModel):
    """Forwarder DNS server check request scheme."""

    dns_server_ips: list[IPv4Address | IPv6Address]


class PrimaryGroupRequest(BaseModel):
    """Request schema for setting primary group."""

    directory_dn: GRANT_DN_STRING
    group_dn: GRANT_DN_STRING
