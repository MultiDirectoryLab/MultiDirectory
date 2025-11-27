"""Main API module, mirrors ldap schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import Depends, Request
from fastapi.routing import APIRouter
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_requests import (
    AddRequest,
    DeleteRequest,
    ModifyDNRequest,
    ModifyRequest,
)
from ldap_protocol.ldap_responses import LDAPResult
from ldap_protocol.utils.queries import set_or_update_primary_group

from .schema import (
    PrimaryGroupRequest,
    SearchRequest,
    SearchResponse,
    SearchResultDone,
)
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


@entry_router.post("/add")
async def add(
    request: AddRequest,
    req: Request,
) -> LDAPResult:
    """LDAP ADD entry request."""
    return await request.handle_api(req.state.dishka_container)


@entry_router.patch("/update")
async def modify(
    request: ModifyRequest,
    req: Request,
) -> LDAPResult:
    """LDAP MODIFY entry request."""
    return await request.handle_api(req.state.dishka_container)


@entry_router.patch("/update_many")
async def modify_many(
    requests: list[ModifyRequest],
    req: Request,
) -> list[LDAPResult]:
    """Bulk LDAP MODIFY entry request."""
    results = []
    for request in requests:
        results.append(await request.handle_api(req.state.dishka_container))
    return results


@entry_router.put("/update/dn")
async def modify_dn(
    request: ModifyDNRequest,
    req: Request,
) -> LDAPResult:
    """LDAP MODIFY entry DN request."""
    return await request.handle_api(req.state.dishka_container)


@entry_router.delete("/delete")
async def delete(
    request: DeleteRequest,
    req: Request,
) -> LDAPResult:
    """LDAP DELETE entry request."""
    return await request.handle_api(req.state.dishka_container)


@entry_router.post("/delete_many")
async def delete_many(
    requests: list[DeleteRequest],
    req: Request,
) -> list[LDAPResult]:
    """Bulk LDAP DELETE entry request."""
    results = []
    for request in requests:
        results.append(await request.handle_api(req.state.dishka_container))
    return results


@entry_router.post("/set_primary_group")
async def set_primary_group(
    request: PrimaryGroupRequest,
    session: FromDishka[AsyncSession],
) -> None:
    """Set primary group for a directory (user or group)."""
    try:
        await set_or_update_primary_group(
            directory_dn=request.directory_dn,
            group_dn=request.group_dn,
            session=session,
        )
    except (ValueError, IntegrityError):
        return None
