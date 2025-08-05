"""Main API module, mirrors ldap schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from dishka.integrations.fastapi import DishkaRoute
from fastapi import Depends, Request
from fastapi.routing import APIRouter

from api.auth.utils import get_ip_from_request
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
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
) -> LDAPResult:
    """LDAP ADD entry request."""
    return await request.handle_api(req.state.dishka_container, ip)


@entry_router.patch("/update")
async def modify(
    request: ModifyRequest,
    req: Request,
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
) -> LDAPResult:
    """LDAP MODIFY entry request."""
    return await request.handle_api(req.state.dishka_container, ip)


@entry_router.patch("/update_many")
async def modify_many(
    requests: list[ModifyRequest],
    req: Request,
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
) -> list[LDAPResult]:
    """Bulk LDAP MODIFY entry request."""
    results = []
    for request in requests:
        results.append(
            await request.handle_api(req.state.dishka_container, ip),
        )
    return results


@entry_router.put("/update/dn")
async def modify_dn(
    request: ModifyDNRequest,
    req: Request,
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
) -> LDAPResult:
    """LDAP MODIFY entry DN request."""
    return await request.handle_api(req.state.dishka_container, ip)


@entry_router.delete("/delete")
async def delete(
    request: DeleteRequest,
    req: Request,
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
) -> LDAPResult:
    """LDAP DELETE entry request."""
    return await request.handle_api(req.state.dishka_container, ip)


@entry_router.post("/delete_many")
async def delete_many(
    requests: list[DeleteRequest],
    req: Request,
    ip: Annotated[IPv4Address | IPv6Address, Depends(get_ip_from_request)],
) -> list[LDAPResult]:
    """Bulk LDAP DELETE entry request."""
    results = []
    for request in requests:
        results.append(
            await request.handle_api(req.state.dishka_container, ip),
        )
    return results
