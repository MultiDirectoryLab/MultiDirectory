"""Main API module, mirrors ldap schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import Depends, Request, status
from fastapi_error_map.routing import ErrorAwareRouter
from fastapi_error_map.rules import rule

from api.error_routing import (
    ERROR_MAP_TYPE,
    DishkaErrorAwareRoute,
    DomainErrorTranslator,
)
from enums import ProjectPartCodes
from ldap_protocol.identity.exceptions import UnauthorizedError
from ldap_protocol.ldap_requests import (
    AddRequest,
    DeleteRequest,
    ModifyDNRequest,
    ModifyRequest,
)
from ldap_protocol.ldap_responses import LDAPResult

from .schema import SearchRequest, SearchResponse, SearchResultDone
from .utils import get_ldap_session

translator = DomainErrorTranslator(ProjectPartCodes.LDAP)


error_map: ERROR_MAP_TYPE = {
    UnauthorizedError: rule(
        status=status.HTTP_401_UNAUTHORIZED,
        translator=translator,
    ),
}

entry_router = ErrorAwareRouter(
    prefix="/entry",
    tags=["LDAP API"],
    route_class=DishkaErrorAwareRoute,
    dependencies=[Depends(get_ldap_session)],
)


@entry_router.post("/search", error_map=error_map)
async def search(
    request: SearchRequest,
    req: Request,
) -> SearchResponse:
    """LDAP SEARCH entry request."""
    responses = await request.handle_api(req.state.dishka_container)
    metadata: SearchResultDone = responses.pop(-1)  # type: ignore

    return SearchResponse(
        result_code=metadata.result_code,
        matchedDN=metadata.matched_dn,
        errorMessage=metadata.error_message,
        search_result=responses,
        total_objects=metadata.total_objects,
        total_pages=metadata.total_pages,
    )


@entry_router.post("/add", error_map=error_map)
async def add(
    request: AddRequest,
    req: Request,
) -> LDAPResult:
    """LDAP ADD entry request."""
    return await request.handle_api(req.state.dishka_container)


@entry_router.patch("/update", error_map=error_map)
async def modify(
    request: ModifyRequest,
    req: Request,
) -> LDAPResult:
    """LDAP MODIFY entry request."""
    return await request.handle_api(req.state.dishka_container)


@entry_router.patch("/update_many", error_map=error_map)
async def modify_many(
    requests: list[ModifyRequest],
    req: Request,
) -> list[LDAPResult]:
    """Bulk LDAP MODIFY entry request."""
    results = []
    for request in requests:
        results.append(await request.handle_api(req.state.dishka_container))
    return results


@entry_router.put("/update/dn", error_map=error_map)
async def modify_dn(
    request: ModifyDNRequest,
    req: Request,
) -> LDAPResult:
    """LDAP MODIFY entry DN request."""
    return await request.handle_api(req.state.dishka_container)


@entry_router.delete("/delete", error_map=error_map)
async def delete(
    request: DeleteRequest,
    req: Request,
) -> LDAPResult:
    """LDAP DELETE entry request."""
    return await request.handle_api(req.state.dishka_container)


@entry_router.post("/delete_many", error_map=error_map)
async def delete_many(
    requests: list[DeleteRequest],
    req: Request,
) -> list[LDAPResult]:
    """Bulk LDAP DELETE entry request."""
    results = []
    for request in requests:
        results.append(await request.handle_api(req.state.dishka_container))
    return results
