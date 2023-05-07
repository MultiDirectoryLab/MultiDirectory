from ldap.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap.ldap_responses import SearchResultDone, SearchResultEntry


class SearchRequest(LDAPSearchRequest):
    __doc__ = LDAPSearchRequest.__doc__
    filter: str  # noqa: A003

    def cast_filter(self, filter, query):
        raise NotImplementedError()


class SearchResponse(SearchResultDone):
    search_result: list[SearchResultEntry]
