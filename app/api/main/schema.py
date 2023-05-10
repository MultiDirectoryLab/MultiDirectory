"""Schemas for main router."""

from ldap.dialogue import Session as LDAPSession
from ldap.filter_interpreter import Filter, cast_str_filter2sql
from ldap.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap.ldap_responses import SearchResultDone, SearchResultEntry


async def handle_user(request, user, session):
    ldap_session = LDAPSession()
    await ldap_session.set_user(user)
    async for response in request.handle(ldap_session, session):
        return response


class SearchRequest(LDAPSearchRequest):  # noqa: D101
    filter: str  # noqa: A003

    def cast_filter(self, filter_, query):
        """Cast str filter to sa sql."""
        filter_ = filter_.lower().replace('objectcategory', 'objectclass')
        return cast_str_filter2sql(Filter.parse(filter_).simplify(), query)


class SearchResponse(SearchResultDone):  # noqa: D101
    search_result: list[SearchResultEntry]
