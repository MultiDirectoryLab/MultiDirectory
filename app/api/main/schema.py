"""Schemas for main router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from functools import cached_property
from ipaddress import IPv4Address, IPv6Address
from typing import final

from dishka import AsyncContainer
from pydantic import BaseModel, Field, PrivateAttr, SecretStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression

from entities import Directory
from ldap_protocol.dns import DNSManagerState, DNSZoneParam, DNSZoneType
from ldap_protocol.filter_interpreter import (
    Filter,
    FilterInterpreterProtocol,
    StringFilterInterpreter,
)
from ldap_protocol.ldap_requests import (
    ModifyDNRequest as LDAPModifyDNRequest,
    ModifyRequest as LDAPModifyRequest,
    SearchRequest as LDAPSearchRequest,
)
from ldap_protocol.ldap_responses import (
    LDAPResult,
    SearchResultDone,
    SearchResultEntry,
)
from ldap_protocol.objects import Changes
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


class PrimaryGroupRequest(BaseModel):
    """Request schema for setting primary group."""

    directory_dn: GRANT_DN_STRING
    group_dn: GRANT_DN_STRING


class RenameRequest(BaseModel):
    """Rename request schema.

    Combines ModifyDN and Modify operations.
    """

    object: str
    newrdn: str
    changes: list[Changes]

    @cached_property
    def _new_object(self) -> str:
        return f"{self.newrdn},{','.join(self.object.split(',')[1:])}"

    @cached_property
    def _oldrdn(self) -> str:
        return self.object.split(",")[0]

    async def _modify_dn_request(
        self,
        container: AsyncContainer,
        entry: str,
        newrdn: str,
    ) -> LDAPResult:
        modify_dn_request = LDAPModifyDNRequest(
            entry=entry,
            newrdn=newrdn,
            deleteoldrdn=True,
            new_superior=None,
        )
        return await modify_dn_request.handle_api(container)

    async def _clear_session_cache(self, container: AsyncContainer) -> None:
        session = await container.get(AsyncSession)
        session.expire_all()

    async def _modify_request(self, container: AsyncContainer) -> LDAPResult:
        modify_request = LDAPModifyRequest(
            object=self._new_object,
            changes=self.changes,
        )
        return await modify_request.handle_api(container)

    async def handle_api(self, container: AsyncContainer) -> LDAPResult:
        """Handle RenameRequest by executing ModifyDN then Modify.

        If ModifyRequest fails, rollback the ModifyDnRequest and return error.
        """
        modify_dn_response = await self._modify_dn_request(
            container,
            self.object,
            self.newrdn,
        )
        if not modify_dn_response or modify_dn_response.result_code != 0:
            return modify_dn_response

        await self._clear_session_cache(container)

        modify_response = await self._modify_request(container)
        if not modify_response or modify_response.result_code != 0:
            await self._modify_dn_request(
                container,
                self._new_object,
                self._oldrdn,
            )

        return modify_response
