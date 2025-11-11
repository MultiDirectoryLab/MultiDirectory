"""Password Policy adapter for FastAPI.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix.conversion import get_converter
from fastapi import status

from api.base_adapter import BaseAdapter
from api.password_policy.schemas import PasswordPolicySchema, PriorityT
from ldap_protocol.permissions_checker import ApiPermissionError
from ldap_protocol.policies.password.dataclasses import PasswordPolicyDTO
from ldap_protocol.policies.password.exceptions import (
    PasswordPolicyAgeDaysError,
    PasswordPolicyAlreadyExistsError,
    PasswordPolicyBaseDnNotFoundError,
    PasswordPolicyCantChangeDefaultDomainError,
    PasswordPolicyCantDeleteError,
    PasswordPolicyDirIsNotUserError,
    PasswordPolicyNotFoundError,
    PasswordPolicyPriorityError,
    PasswordPolicyUpdatePrioritiesError,
)
from ldap_protocol.policies.password.use_cases import PasswordPolicyUseCases

_convert_schema_to_dto = get_converter(PasswordPolicySchema, PasswordPolicyDTO)
_convert_dto_to_schema = get_converter(
    PasswordPolicyDTO[int, int],
    PasswordPolicySchema[int, int],
)


class PasswordPolicyFastAPIAdapter(BaseAdapter[PasswordPolicyUseCases]):
    """Adapter for password policies."""

    _exceptions_map: dict[type[Exception], int] = {
        PasswordPolicyBaseDnNotFoundError: status.HTTP_404_NOT_FOUND,
        PasswordPolicyNotFoundError: status.HTTP_404_NOT_FOUND,
        PasswordPolicyDirIsNotUserError: status.HTTP_404_NOT_FOUND,
        PasswordPolicyAlreadyExistsError: status.HTTP_409_CONFLICT,
        PasswordPolicyCantChangeDefaultDomainError: status.HTTP_400_BAD_REQUEST,  # noqa: E501
        PasswordPolicyCantDeleteError: status.HTTP_400_BAD_REQUEST,
        PasswordPolicyUpdatePrioritiesError: status.HTTP_400_BAD_REQUEST,
        PasswordPolicyPriorityError: status.HTTP_400_BAD_REQUEST,
        PasswordPolicyAgeDaysError: status.HTTP_400_BAD_REQUEST,
        ApiPermissionError: status.HTTP_403_FORBIDDEN,
    }

    async def get_all(self) -> list[PasswordPolicySchema[int, int]]:
        """Get all Password Policies."""
        dtos = await self._service.get_all()
        return list(map(_convert_dto_to_schema, dtos))

    async def get(self, id_: int) -> PasswordPolicySchema[int, int]:
        """Get one Password Policy."""
        dto = await self._service.get(id_)
        return _convert_dto_to_schema(dto)

    async def get_password_policy_by_dir_path_dn(
        self,
        path_dn: str,
    ) -> PasswordPolicySchema[int, int]:
        """Get one Password Policy for one Directory by its path."""
        dto = await self._service.get_password_policy_by_dir_path_dn(
            path_dn,
        )
        return _convert_dto_to_schema(dto)

    async def update(
        self,
        id_: int,
        policy: PasswordPolicySchema[int, PriorityT],
    ) -> None:
        """Update one Password Policy."""
        dto = _convert_schema_to_dto(policy)
        await self._service.update(id_, dto)

    async def reset_domain_policy_to_default_config(self) -> None:
        """Reset domain Password Policy to default configuration."""
        await self._service.reset_domain_policy_to_default_config()

    async def turnoff(self, id_: int) -> None:
        """Turn off one Password Policy."""
        await self._service.turnoff(id_)
