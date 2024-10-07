"""Schemas for main router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import AsyncContainer
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression

from ldap_protocol.filter_interpreter import Filter, cast_str_filter2sql
from ldap_protocol.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap_protocol.ldap_requests.base import BaseResponse
from ldap_protocol.ldap_responses import SearchResultDone, SearchResultEntry


class SearchRequest(LDAPSearchRequest):
    """Search request for web api."""

    filter: str = Field(  # noqa: A003
        ..., examples=["(objectClass=*)"])  # type: ignore

    def cast_filter(self) -> UnaryExpression | ColumnElement:
        """Cast str filter to sa sql."""
        filter_ = self.filter.lower().replace("objectcategory", "objectclass")
        return cast_str_filter2sql(Filter.parse(filter_).simplify())

    async def handle_api(  # type: ignore
        self,
        container: AsyncContainer,
    ) -> list[BaseResponse]:
        """Get all responses."""
        return await self._handle_api(container)


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
