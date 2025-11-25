"""Password Policy router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from fastapi import Depends
from fastapi_error_map.routing import ErrorAwareRouter

from api.auth.utils import verify_auth
from api.error_routing import DishkaErrorAwareRoute
from api.password_policy.adapter import PasswordPolicyFastAPIAdapter
from api.password_policy.error_utils import error_map
from api.password_policy.schemas import PasswordPolicySchema
from ldap_protocol.utils.const import GRANT_DN_STRING

from .schemas import PriorityT

password_policy_router = ErrorAwareRouter(
    prefix="/password-policy",
    dependencies=[Depends(verify_auth)],
    tags=["Password Policy"],
    route_class=DishkaErrorAwareRoute,
)


@password_policy_router.get("/all", error_map=error_map)
async def get_all(
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> list[PasswordPolicySchema[int]]:
    """Get all Password Policies."""
    return await adapter.get_all()


@password_policy_router.get("/{id_}", error_map=error_map)
async def get(
    id_: int,
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> PasswordPolicySchema[int]:
    """Get one Password Policy."""
    return await adapter.get(id_)


@password_policy_router.get("/by_dir_path_dn/{path_dn}", error_map=error_map)
async def get_password_policy_by_dir_path_dn(
    path_dn: GRANT_DN_STRING,
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> PasswordPolicySchema[int]:
    """Get one Password Policy for one Directory by its path."""
    return await adapter.get_password_policy_by_dir_path_dn(path_dn)


@password_policy_router.put("/{id_}", error_map=error_map)
async def update(
    id_: int,
    policy: PasswordPolicySchema[PriorityT],
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> None:
    """Update one Password Policy."""
    await adapter.update(id_, policy)


@password_policy_router.put("/reset/domain_policy", error_map=error_map)
async def reset_domain_policy_to_default_config(
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> None:
    """Reset domain Password Policy to default configuration."""
    await adapter.reset_domain_policy_to_default_config()
