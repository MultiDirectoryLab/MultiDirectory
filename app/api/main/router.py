from fastapi import Depends
from fastapi.routing import APIRouter

from api.auth import User, get_current_user, get_current_user_or_none
from ldap.ldap_requests import AddRequest, ModifyDNRequest, ModifyRequest
from ldap.ldap_responses import LDAPCodes, LDAPResult
from models.database import AsyncSession, get_session

from .schema import SearchRequest, SearchResponse, SearchResultDone

entry_router = APIRouter(prefix='/entry')


@entry_router.post('/search')
async def search(
    request: SearchRequest,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(get_current_user_or_none),
) -> SearchResponse:
    """Search request, fields descriped in RFC."""
    response_list = []
    async for response in request.get_result(bool(user), session):
        response_list.append(response)

    search_done: SearchResultDone = response_list.pop(-1)
    return SearchResponse(
        resultCode=search_done.result_code,
        matchedDN=search_done.matched_dn,
        errorMessage=search_done.error_message,
        search_result=response_list,
    )


@entry_router.post('/add')
async def add(
    request: AddRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> LDAPResult:
    return LDAPResult(result_code=LDAPCodes.SUCCESS)


@entry_router.patch('/update')
async def update(
    request: ModifyRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> LDAPResult:
    return LDAPResult(result_code=LDAPCodes.SUCCESS)


@entry_router.put('/update/dn')
async def update_dn(
    request: ModifyDNRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> LDAPResult:
    return LDAPResult(result_code=LDAPCodes.SUCCESS)


@entry_router.delete('/delete')
async def delete(
    object: str,  # noqa: A002
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> LDAPResult:
    return LDAPResult(result_code=LDAPCodes.SUCCESS)
