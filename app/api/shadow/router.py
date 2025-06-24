"""Shadow api.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from ipaddress import IPv4Address
from typing import Annotated

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Body, HTTPException, status

from api.utils import (
    # MFAError,
    # PasswordError,
    ShadowMFAService,
    ShadowPasswordService,
)
from api.utils.exceptions import (
    ForbiddenError,
    MFAError,
    NotFoundError,
    PolicyError,
)
from ldap_protocol.multifactor import LDAPMultiFactorAPI

shadow_router = APIRouter(route_class=DishkaRoute)


@shadow_router.post("/mfa/push")
async def proxy_request(
    principal: Annotated[str, Body(embed=True)],
    ip: Annotated[IPv4Address, Body(embed=True)],
    mfa: FromDishka[LDAPMultiFactorAPI],
    shadow_mfa_service: FromDishka[ShadowMFAService],
) -> None:
    try:
        await shadow_mfa_service.proxy_request(principal, ip)
    except NotFoundError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )
    except ForbiddenError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except MFAError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    except HTTPException as exc:
        raise exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )


@shadow_router.post("/sync/password")
async def sync_password(
    principal: Annotated[str, Body(embed=True)],
    new_password: Annotated[str, Body(embed=True)],
    shadow_password_service: FromDishka[ShadowPasswordService],
) -> None:
    try:
        await shadow_password_service.sync_password(principal, new_password)
    except NotFoundError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )
    except PolicyError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )
    except HTTPException as exc:
        raise exc
    except Exception as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        )
