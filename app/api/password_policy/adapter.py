"""Password Policy adapter for FastAPI.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix.conversion import get_converter
from fastapi import status

from api.base_adapter import BaseAdapter
from ldap_protocol.policies.password.dataclasses import PasswordPolicyDTO
from ldap_protocol.policies.password.exceptions import (
    PasswordPolicyAlreadyExistsError,
    PasswordPolicyCantChangeDefaultDomainError,
    PasswordPolicyCantDeleteError,
    PasswordPolicyNotFoundError,
    PasswordPolicyUpdatePrioritiesError,
)
from ldap_protocol.policies.password.schemas import PasswordPolicySchema
from ldap_protocol.policies.password.use_case import PasswordPolicyUseCases

_convert_schema_to_dto = get_converter(PasswordPolicySchema, PasswordPolicyDTO)
_convert_dto_to_schema = get_converter(
    PasswordPolicyDTO[int, int],
    PasswordPolicySchema[int, int],
)


class PasswordPolicyAdapter(BaseAdapter[PasswordPolicyUseCases]):
    """Adapter for password policies."""

    _exceptions_map: dict[type[Exception], int] = {
        PasswordPolicyNotFoundError: status.HTTP_404_NOT_FOUND,
        PasswordPolicyAlreadyExistsError: status.HTTP_409_CONFLICT,
        PasswordPolicyCantChangeDefaultDomainError: status.HTTP_400_BAD_REQUEST,  # noqa: E501
        PasswordPolicyCantDeleteError: status.HTTP_400_BAD_REQUEST,
        PasswordPolicyUpdatePrioritiesError: status.HTTP_400_BAD_REQUEST,
    }

    async def get_all(self) -> list[PasswordPolicySchema[int, int]]:
        """Get all Password Policies."""
        dtos = await self._service.get_all()
        return list(map(_convert_dto_to_schema, dtos))

    async def get(self, id_: int) -> PasswordPolicySchema[int, int]:
        """Get one Password Policy."""
        dto = await self._service.get(id_)
        return _convert_dto_to_schema(dto)

    async def get_result(
        self,
        user_path: str,
    ) -> PasswordPolicySchema[int, int]:
        """Get one Password Policy."""
        dto = await self._service.get_result(user_path)
        return _convert_dto_to_schema(dto)

    async def create(
        self,
        policy: PasswordPolicySchema[None, int | None],
    ) -> None:
        """Create one Password Policy."""
        dto = _convert_schema_to_dto(policy)
        await self._service.create(dto)

    async def update(
        self,
        id_: int,
        policy: PasswordPolicySchema[int, int | None],
    ) -> None:
        """Update one Password Policy."""
        dto = _convert_schema_to_dto(policy)
        await self._service.update(id_, dto)

    async def delete(self, id_: int) -> None:
        """Delete one Password Policy."""
        await self._service.delete(id_)

    async def reset_domain_policy_to_default_config(self) -> None:
        """Reset domain Password Policy to default configuration."""
        await self._service.reset_domain_policy_to_default_config()

    async def update_priorities(
        self,
        new_priorities: dict[int, int],
    ) -> None:
        """Update priority of all Password Policies."""
        await self._service.update_priorities(new_priorities)

    async def turnoff(self, id_: int) -> None:
        """Turn off one Password Policy."""
        await self._service.turnoff(id_)
