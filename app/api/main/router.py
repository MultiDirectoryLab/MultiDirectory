"""Main API module, mirrors ldap schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka.integrations.fastapi import inject
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

entry_router = APIRouter(prefix='/entry', tags=['LDAP API'])


@entry_router.post('/search', dependencies=[Depends(get_ldap_session)])
@inject
async def search(
    request: SearchRequest,
    req: Request,
) -> SearchResponse:
    """LDAP SEARCH entry request."""
    responses = await request.handle_api(req.state.dishka_container)
    metadata: SearchResultDone = responses.pop(-1)

    return SearchResponse(
        result_code=metadata.result_code,
        matchedDN=metadata.matched_dn,
        errorMessage=metadata.error_message,
        search_result=responses,
        total_objects=metadata.total_objects,
        total_pages=metadata.total_pages,
    )


@entry_router.post('/add', dependencies=[Depends(get_ldap_session)])
@inject
async def add(
    request: AddRequest,
    req: Request,
) -> LDAPResult:
    """LDAP ADD entry request."""
    return await request.handle_api(req.state.dishka_container)


@entry_router.patch('/update', dependencies=[Depends(get_ldap_session)])
@inject
async def modify(
    request: ModifyRequest,
    req: Request,
) -> LDAPResult:
    """LDAP MODIFY entry request."""
    return await request.handle_api(req.state.dishka_container)


@entry_router.put('/update/dn', dependencies=[Depends(get_ldap_session)])
@inject
async def modify_dn(
    request: ModifyDNRequest,
    req: Request,
) -> LDAPResult:
    """LDAP MODIFY entry DN request."""
    return await request.handle_api(req.state.dishka_container)


@entry_router.delete('/delete', dependencies=[Depends(get_ldap_session)])
@inject
async def delete(
    request: DeleteRequest,
    req: Request,
) -> LDAPResult:
    """LDAP DELETE entry request."""
    return await request.handle_api(req.state.dishka_container)
