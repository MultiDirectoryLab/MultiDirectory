"""Schemas for main router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import final

from dishka import AsyncContainer
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression

from ldap_protocol.dns import DNSManagerState, DNSZoneParam, DNSZoneType
from ldap_protocol.filter_interpreter import Filter, cast_str_filter2sql
from ldap_protocol.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap_protocol.ldap_responses import SearchResultDone, SearchResultEntry


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
    zone_name: str | None = Field(None)

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


class DNSServiceZoneCreateRequest(BaseModel):
    """DNS zone create request scheme."""

    zone_name: str
    zone_type: DNSZoneType
    acl: list[str]
    params: list[DNSZoneParam]


class DNSServiceZoneUpdateRequest(BaseModel):
    """DNS zone update request scheme."""

    zone_name: str
    acl: list[str]
    params: list[DNSZoneParam] | None = Field(None)


class DNSServiceZoneDeleteRequest(BaseModel):
    """DNS zone delete request scheme."""

    zone_names: list[str]


class DNSServiceReloadZoneRequest(BaseModel):
    """DNS zone reload request scheme."""

    zone_name: str


class DNSServiceForwardZoneCheckRequest(BaseModel):
    """Forwarder DNS server check request scheme."""

    dns_server_ips: list[str]


class DNSServiceOptionsUpdateRequest(BaseModel):
    """DNS server options update request scheme."""

    name: str
    value: str | list[str] = Field("")
