"""Schemas for main router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import final

from dishka import AsyncContainer
from pydantic import BaseModel, Field, SecretStr, field_serializer
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression

from ldap_protocol.dns import DNSManagerState
from ldap_protocol.filter_interpreter import Filter, cast_str_filter2sql
from ldap_protocol.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap_protocol.ldap_responses import SearchResultDone, SearchResultEntry
from models import (
    AuditDestinationProtocolType,
    AuditDestinationServiceType,
    AuditSeverity,
)


class SearchRequest(LDAPSearchRequest):
    """Search request for web api."""

    filter: str = Field(..., examples=["(objectClass=*)"])  # type: ignore

    def cast_filter(self) -> UnaryExpression | ColumnElement:
        """Cast str filter to sa sql."""
        filter_ = self.filter.lower().replace("objectcategory", "objectclass")
        return cast_str_filter2sql(Filter.parse(filter_).simplify())

    @final
    async def handle_api(  # type: ignore
        self,
        container: AsyncContainer,
        ip: IPv4Address | IPv6Address,
    ) -> list[SearchResultEntry | SearchResultDone]:
        """Get all responses."""
        return await self._handle_api(container, ip)  # type: ignore


class SearchResponse(SearchResultDone):
    """Search response for web api."""

    search_result: list[SearchResultEntry]


class KerberosSetupRequest(BaseModel):
    """Kerberos setup data."""

    krbadmin_password: SecretStr
    admin_password: SecretStr
    stash_password: SecretStr


class _PolicyFields:
    name: str
    can_read: bool
    can_add: bool
    can_modify: bool
    directories: list[str]
    groups: list[str]


class _MaterialFields:
    id: int


class AccessPolicySchema(_PolicyFields, BaseModel):
    """AP Schema w/o id."""


class MaterialAccessPolicySchema(_PolicyFields, _MaterialFields, BaseModel):
    """AP Schema with id."""


class DNSServiceSetupRequest(BaseModel):
    """DNS setup request schema."""

    dns_status: DNSManagerState
    domain: str
    dns_ip_address: str | None = Field(None)
    tsig_key: str | None = Field(None)


class DNSServiceRecordBaseRequest(BaseModel):
    """DNS setup base schema."""

    record_name: str
    record_type: str


class DNSServiceRecordCreateRequest(DNSServiceRecordBaseRequest):
    """DNS create request schema."""

    record_value: str
    ttl: int | None = Field(None)


class DNSServiceRecordDeleteRequest(DNSServiceRecordBaseRequest):
    """DNS delete request schema."""

    record_value: str


class DNSServiceRecordUpdateRequest(DNSServiceRecordBaseRequest):
    """DNS update request schema."""

    record_value: str | None = Field(None)
    ttl: int | None = Field(None)


class AuditPolicySchema(BaseModel):
    """Audit policy schema."""

    id: int
    name: str
    severity: AuditSeverity
    is_enabled: bool

    @field_serializer("severity")
    def serialize_severity(self, severity: AuditSeverity) -> str:
        return severity.name.lower()


class AuditDestinationSchemaRequest(BaseModel):
    """Audit destination request schema."""

    name: str
    service_type: AuditDestinationServiceType
    is_enabled: bool
    host: str
    port: int
    protocol: AuditDestinationProtocolType

    class Config:  # noqa: D106
        use_enum_values = True


class AuditDestinationSchema(_MaterialFields, AuditDestinationSchemaRequest):
    """Audit destination schema."""
