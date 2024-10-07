"""Schemas for main router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
from typing import Optional

from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.sql.elements import UnaryExpression

from ldap_protocol.dns import DNSRecordType, DNSManagerState
from ldap_protocol.filter_interpreter import Filter, cast_str_filter2sql
from ldap_protocol.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap_protocol.ldap_requests.base import APIMultipleResponseMixin
from ldap_protocol.ldap_responses import SearchResultDone, SearchResultEntry


class SearchRequest(APIMultipleResponseMixin, LDAPSearchRequest):  # noqa: D101
    filter: str = Field(..., examples=["(objectClass=*)"])  # noqa: A003

    def cast_filter(self, filter_: str) -> UnaryExpression:
        """Cast str filter to sa sql."""
        filter_ = filter_.lower().replace('objectcategory', 'objectclass')
        return cast_str_filter2sql(
            Filter.parse(filter_).simplify())


class SearchResponse(SearchResultDone):  # noqa: D101
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
    id: int  # noqa: A003


class AccessPolicySchema(_PolicyFields, BaseModel):
    """AP Schema w/o id."""


class MaterialAccessPolicySchema(_PolicyFields, _MaterialFields, BaseModel):
    """AP Schema with id."""


class DNSServiceSetupRequest(BaseModel):
    dns_status: DNSManagerState
    domain: str
    dns_ip_address: Optional[str] = Field(None)
    tsig_key: Optional[str] = Field(None)


class DNSServiceRecordRequest(BaseModel):
    record_name: str
    record_type: str
    record_value: Optional[str]
    ttl: Optional[int] = Field(None)
