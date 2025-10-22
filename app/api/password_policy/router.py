"""Password Policy routers.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from dishka import FromDishka
from dishka.integrations.fastapi import DishkaRoute
from fastapi import APIRouter, Depends, status

from api.auth import get_current_user
from api.password_policy.adapter import PasswordPolicyFastAPIAdapter
from api.password_policy.schemas import PasswordPolicySchema

from .schemas import _PriorityT

pwd_router = APIRouter(
    prefix="/password-policy",
    dependencies=[Depends(get_current_user)],
    tags=["Password Policy"],
    route_class=DishkaRoute,
)


@pwd_router.get(
    "/all",
    response_model=list[PasswordPolicySchema[int, int]],
)
async def get_all(
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> list[PasswordPolicySchema[int, int]]:
    """Get all Password Policies."""
    return await adapter.get_all()


@pwd_router.get(
    "/{id_}",
    response_model=PasswordPolicySchema[int, int],
)
async def get(
    id_: int,
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> PasswordPolicySchema[int, int]:
    """Get one Password Policy."""
    return await adapter.get(id_)


@pwd_router.get(
    "/by_dir_path/{directory_path}",
    response_model=PasswordPolicySchema[int, int],
)
async def get_password_policy_by_dir_path(
    directory_path: str,
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> PasswordPolicySchema[int, int]:
    """Get one Password Policy for one Directory by its path."""
    return await adapter.get_password_policy_by_dir_path(directory_path)


@pwd_router.post("", status_code=status.HTTP_201_CREATED)
async def create(
    policy: PasswordPolicySchema[None, _PriorityT],
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> None:
    """Create one Password Policy."""
    await adapter.create(policy)


@pwd_router.put("/{id_}")
async def update(
    id_: int,
    policy: PasswordPolicySchema[int, _PriorityT],
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> None:
    """Update one Password Policy."""
    await adapter.update(id_, policy)


@pwd_router.delete("/{id_}")
async def delete(
    id_: int,
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> None:
    """Delete one Password Policy."""
    await adapter.delete(id_)


@pwd_router.put("/reset/domain_policy_to_default_config")
async def reset_domain_policy_to_default_config(
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> None:
    """Reset domain Password Policy to default configuration."""
    await adapter.reset_domain_policy_to_default_config()


@pwd_router.put("/update/priorities")
async def update_priorities(
    new_priorities: dict[int, int],
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> None:
    """Update priority of all Password Policies."""
    await adapter.update_priorities(new_priorities)


@pwd_router.put("/turnoff/{id_}")
async def turnoff(
    id_: int,
    adapter: FromDishka[PasswordPolicyFastAPIAdapter],
) -> None:
    """Turn off one Password Policy."""
    await adapter.turnoff(id_)
