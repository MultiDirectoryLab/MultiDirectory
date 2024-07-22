"""Main API module, mirrors ldap schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import inject
from fastapi.routing import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.dialogue import LDAPSession as LDAPSession
from ldap_protocol.ldap_requests import (
    AddRequest,
    DeleteRequest,
    ModifyDNRequest,
    ModifyRequest,
)
from ldap_protocol.ldap_responses import LDAPResult

from .schema import SearchRequest, SearchResponse, SearchResultDone

entry_router = APIRouter(prefix='/entry', tags=['LDAP API'])


@entry_router.post('/search')
@inject
async def search(
    request: SearchRequest,
    session: FromDishka[AsyncSession],
    ldap_session: FromDishka[LDAPSession],
) -> SearchResponse:
    """LDAP SEARCH entry request."""
    responses = await request.handle_api(ldap_session, session)
    metadata: SearchResultDone = responses.pop(-1)

    return SearchResponse(
        result_code=metadata.result_code,
        matchedDN=metadata.matched_dn,
        errorMessage=metadata.error_message,
        search_result=responses,
        total_objects=metadata.total_objects,
        total_pages=metadata.total_pages,
    )


@entry_router.post('/add')
@inject
async def add(
    request: AddRequest,
    session: FromDishka[AsyncSession],
    ldap_session: FromDishka[LDAPSession],
) -> LDAPResult:
    """LDAP ADD entry request."""
    return await request.handle_api(ldap_session, session)


@entry_router.patch('/update')
@inject
async def modify(
    request: ModifyRequest,
    session: FromDishka[AsyncSession],
    ldap_session: FromDishka[LDAPSession],
) -> LDAPResult:
    """LDAP MODIFY entry request."""
    return await request.handle_api(ldap_session, session)


@entry_router.put('/update/dn')
@inject
async def modify_dn(
    request: ModifyDNRequest,
    session: FromDishka[AsyncSession],
    ldap_session: FromDishka[LDAPSession],
) -> LDAPResult:
    """LDAP MODIFY entry DN request."""
    return await request.handle_api(ldap_session, session)


@entry_router.delete('/delete')
@inject
async def delete(
    request: DeleteRequest,
    session: FromDishka[AsyncSession],
    ldap_session: FromDishka[LDAPSession],
) -> LDAPResult:
    """LDAP DELETE entry request."""
    return await request.handle_api(ldap_session, session)
