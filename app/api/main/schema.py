"""Schemas for main router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime
import uuid
from ipaddress import IPv4Address, IPv6Address
from typing import final
from uuid import UUID

from dishka import AsyncContainer
from pydantic import BaseModel, Field, PrivateAttr, SecretStr
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression

from ldap_protocol.dns import DNSManagerState, DNSZoneParam, DNSZoneType
from ldap_protocol.filter_interpreter import (
    Filter,
    FilterInterpreterProtocol,
    StringFilterInterpreter,
)
from ldap_protocol.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap_protocol.ldap_responses import SearchResultDone, SearchResultEntry
from models import Directory


class SearchRequest(LDAPSearchRequest):
    """Search request for web api."""

    filter: str = Field(..., examples=["(objectClass=*)"])  # type: ignore

    _filter_interpreter: FilterInterpreterProtocol = PrivateAttr(
        default_factory=StringFilterInterpreter,
    )

    def cast_filter(self) -> UnaryExpression | ColumnElement:
        """Cast str filter to sa sql."""
        filter_ = self.filter.lower().replace("objectcategory", "objectclass")
        return self._filter_interpreter.cast_to_sql(
            Filter.parse(filter_).simplify(),
        )

    def get_directory_attr_value(  # type: ignore
        self,
        directory: Directory,
        attr: str,
    ) -> int | str | bytes | uuid.UUID | datetime:
        return getattr(directory, attr)

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


class DNSServiceSetupRequest(BaseModel):
    """DNS setup request schema."""

    dns_status: DNSManagerState
    domain: str
    dns_ip_address: IPv4Address | IPv6Address | None = None
    tsig_key: str | None = None


class DNSServiceRecordBaseRequest(BaseModel):
    """DNS setup base schema."""

    record_name: str
    record_type: str
    zone_name: str | None = None


class DNSServiceRecordCreateRequest(DNSServiceRecordBaseRequest):
    """DNS create request schema."""

    record_value: str
    ttl: int | None = None


class DNSServiceRecordDeleteRequest(DNSServiceRecordBaseRequest):
    """DNS delete request schema."""

    record_value: str


class DNSServiceRecordUpdateRequest(DNSServiceRecordBaseRequest):
    """DNS update request schema."""

    record_value: str | None = None
    ttl: int | None = None


class DNSServiceZoneCreateRequest(BaseModel):
    """DNS zone create request scheme."""

    zone_name: str
    zone_type: DNSZoneType
    nameserver: str | None = None
    params: list[DNSZoneParam]


class DNSServiceZoneUpdateRequest(BaseModel):
    """DNS zone update request scheme."""

    zone_name: str
    params: list[DNSZoneParam]


class DNSServiceZoneDeleteRequest(BaseModel):
    """DNS zone delete request scheme."""

    zone_names: list[str]


class DNSServiceReloadZoneRequest(BaseModel):
    """DNS zone reload request scheme."""

    zone_name: str


class DNSServiceForwardZoneCheckRequest(BaseModel):
    """Forwarder DNS server check request scheme."""

    dns_server_ips: list[IPv4Address | IPv6Address]


class DNSServiceOptionsUpdateRequest(BaseModel):
    """DNS server options update request scheme."""

    name: str
    value: str | list[str] = ""
