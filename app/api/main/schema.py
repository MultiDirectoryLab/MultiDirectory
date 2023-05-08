"""Schemas for main router."""

from ldap.filter_interpreter import Filter, cast_str_filter2sql
from ldap.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap.ldap_responses import SearchResultDone, SearchResultEntry


class SearchRequest(LDAPSearchRequest):
    filter: str  # noqa: A003

    def cast_filter(self, filter_, query):
        """Cast str filter to sa sql."""
        filter_ = filter_.lower().replace('objectcategory', 'objectclass')
        return cast_str_filter2sql(Filter.parse(filter_).simplify(), query)


class SearchResponse(SearchResultDone):
    search_result: list[SearchResultEntry]
