"""Schemas for main router."""

from pydantic import AnyUrl, BaseModel, Field

from ldap.filter_interpreter import Filter, cast_str_filter2sql
from ldap.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap.ldap_responses import SearchResultDone, SearchResultEntry


class SearchRequest(LDAPSearchRequest):  # noqa: D101
    filter: str = Field(..., example="(objectClass=*)")  # noqa: A003

    def cast_filter(self, filter_, query):
        """Cast str filter to sa sql."""
        filter_ = filter_.lower().replace('objectcategory', 'objectclass')
        return cast_str_filter2sql(Filter.parse(filter_).simplify(), query)


class SearchResponse(SearchResultDone):  # noqa: D101
    search_result: list[SearchResultEntry]


class SetupRequest(BaseModel):
    """Setup app form."""

    domain: AnyUrl
    username: str
    user_principal_name: str
    display_name: str
    password: str
