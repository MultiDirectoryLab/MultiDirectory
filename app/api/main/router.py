"""Main API module, mirrors ldap schema."""

from typing import Annotated

from fastapi.params import Depends
from fastapi.routing import APIRouter

from api.auth import User, get_current_user_or_none
from ldap_protocol.ldap_requests import (
    AddRequest,
    DeleteRequest,
    ModifyDNRequest,
    ModifyRequest,
)
from ldap_protocol.ldap_responses import LDAPResult
from models.database import AsyncSession, get_session

from .schema import SearchRequest, SearchResponse, SearchResultDone

entry_router = APIRouter(prefix='/entry', tags=['LDAP API'])


@entry_router.post('/search')
async def search(
    request: SearchRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User | None, Depends(get_current_user_or_none)],
) -> SearchResponse:
    """LDAP SEARCH entry request."""
    responses = await request.handle_api(user, session, False)
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
async def add(
    request: AddRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User | None, Depends(get_current_user_or_none)],
) -> LDAPResult:
    """LDAP ADD entry request."""
    return await request.handle_api(user, session)


@entry_router.patch('/update')
async def update(
    request: ModifyRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user_or_none)],
) -> LDAPResult:
    """LDAP UPDATE entry request."""
    return await request.handle_api(user, session)


@entry_router.put('/update/dn')
async def update_dn(
    request: ModifyDNRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user_or_none)],
) -> LDAPResult:
    """LDAP UPDATE entry DN request."""
    return await request.handle_api(user, session)


@entry_router.delete('/delete')
async def delete(
    request: DeleteRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(get_current_user_or_none)],
) -> LDAPResult:
    """LDAP DELETE entry request."""
    return await request.handle_api(user, session)
