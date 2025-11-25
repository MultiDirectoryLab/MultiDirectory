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
from ldap_protocol.objects import Changes, Operation, PartialAttribute

from .schema import (
    SearchRequest,
    SearchResponse,
    SearchResultDone,
    SetPrimaryGroupRequest,
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
    request: SetPrimaryGroupRequest,
    req: Request,
) -> None:
    """Set primary group for a directory (user or group).

    This endpoint allows setting a primary group for a user or group.
    The group must be a member of the directory's groups, or it will
    be added automatically.

    Args:
        request: SetPrimaryGroupRequest with directory_dn and group_dn.
        req: FastAPI request object.

    """
    modify_request = ModifyRequest(
        object=request.directory_dn,
        changes=[
            Changes(
                operation=Operation.REPLACE,
                modification=PartialAttribute(
                    type="primaryGroupID",
                    vals=[request.group_dn],
                ),
            ),
        ],
    )
    await modify_request.handle_api(req.state.dishka_container)
