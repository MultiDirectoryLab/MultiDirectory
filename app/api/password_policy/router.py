"""Password Policy routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Depends

from api.auth import get_current_user
from api.password_policy.adapter import PasswordPolicyFastAPIAdapter
from api.password_policy.schemas import PasswordPolicySchema
from ldap_protocol.utils.const import GRANT_DN_STRING

from .schemas import PriorityT

password_policy_router = APIRouter(
    prefix="/password-policy",
    dependencies=[Depends(get_current_user)],
    tags=["Password Policy"],
    route_class=DishkaRoute,
)


@password_policy_router.get("/all")
async def get_all(
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> list[PasswordPolicySchema[int, int]]:
    """Get all Password Policies."""
    return await adapter.get_all()


@password_policy_router.get("/{id_}")
async def get(
    id_: int,
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> PasswordPolicySchema[int, int]:
    """Get one Password Policy."""
    return await adapter.get(id_)


@password_policy_router.get("/by_dir_path_dn/{path_dn}")
async def get_password_policy_by_dir_path_dn(
    path_dn: GRANT_DN_STRING,
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> PasswordPolicySchema[int, int]:
    """Get one Password Policy for one Directory by its path."""
    return await adapter.get_password_policy_by_dir_path_dn(path_dn)


@password_policy_router.put("/{id_}")
async def update(
    id_: int,
    policy: PasswordPolicySchema[int, PriorityT],
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> None:
    """Update one Password Policy."""
    await adapter.update(id_, policy)


@password_policy_router.put("/reset/domain_policyg")
async def reset_domain_policy_to_default_config(
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> None:
    """Reset domain Password Policy to default configuration."""
    await adapter.reset_domain_policy_to_default_config()


@password_policy_router.put("/turnoff/{id_}")
async def turnoff(
    id_: int,
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> None:
    """Turn off one Password Policy."""
    await adapter.turnoff(id_)
