"""Main API module, mirrors ldap schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka.integrations.fastapi import DishkaRoute
from fastapi import Depends, Request
from fastapi.routing import APIRouter

from ldap_protocol.ldap_requests import (
    AddRequest,
    DeleteRequest,
    ModifyDNRequest,
    ModifyRequest,
)
from ldap_protocol.ldap_responses import LDAPResult

from .schema import SearchRequest, SearchResponse, SearchResultDone
from .utils import get_ldap_session

entry_router = APIRouter(
    prefix="/entry",
    tags=["LDAP API"],
    route_class=DishkaRoute,
    dependencies=[Depends(get_ldap_session)],
)


@entry_router.post("/search")
async def search(
    request: SearchRequest,
    req: Request,
) -> SearchResponse:
    """Handle LDAP SEARCH entry request.

    Args:
        request (SearchRequest): object containing search parameters.
        req (Request): object for accessing application state.

    Returns:
        SearchResponse: Response containing search results and metadata.
    """
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


@entry_router.post("/add")
async def add(
    request: AddRequest,
    req: Request,
) -> LDAPResult:
    """Handle LDAP ADD entry request.

    Args:
        request (AddRequest): object containing entry data to add.
        req (Request): object for accessing application state.

    Returns:
        LDAPResult: Result of the add operation.
    """
    return await request.handle_api(req.state.dishka_container)


@entry_router.patch("/update")
async def modify(
    request: ModifyRequest,
    req: Request,
) -> LDAPResult:
    """Handle LDAP MODIFY entry request.

    Args:
        request (ModifyRequest): object containing modification data.
        req (Request): object for accessing application state.

    Returns:
        LDAPResult: Result of the modify operation.
    """
    return await request.handle_api(req.state.dishka_container)


@entry_router.patch("/update_many")
async def modify_many(
    requests: list[ModifyRequest],
    req: Request,
) -> list[LDAPResult]:
    """Handle bulk LDAP MODIFY entry requests.

    Args:
        requests (list[ModifyRequest]): List of ModifyRequest objects\
            containing modification data.
        req (Request): object for accessing application state.

    Returns:
        list[LDAPResult]: List of results for each modify operation.
    """
    results = []
    for request in requests:
        results.append(await request.handle_api(req.state.dishka_container))
    return results


@entry_router.put("/update/dn")
async def modify_dn(
    request: ModifyDNRequest,
    req: Request,
) -> LDAPResult:
    """Handle LDAP MODIFY entry DN request.

    Args:
        request (ModifyDNRequest): object containing DN modification data.
        req (Request): object for accessing application state.

    Returns:
        LDAPResult: Result of the DN modify operation.
    """
    return await request.handle_api(req.state.dishka_container)


@entry_router.delete("/delete")
async def delete(
    request: DeleteRequest,
    req: Request,
) -> LDAPResult:
    """Handle LDAP DELETE entry request.

    Args:
        request (DeleteRequest): object containing entry to delete.
        req (Request): object for accessing application state.

    Returns:
        LDAPResult: Result of the delete operation.
    """
    return await request.handle_api(req.state.dishka_container)
