"""Adapter for password policies.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from adaptix.conversion import get_converter
from fastapi import status

from api.base_adapter import BaseAdapter
from api.password_policy.schemas import PasswordPolicySchema
from ldap_protocol.policies.password.dataclasses import PasswordPolicyDTO
from ldap_protocol.policies.password.exceptions import (
    PasswordPolicyAlreadyExistsError,
    PasswordPolicyNotFoundError,
)
from ldap_protocol.policies.password.service import PasswordPolicyService

_convert_schema_to_dto = get_converter(PasswordPolicySchema, PasswordPolicyDTO)
_convert_dto_to_schema = get_converter(PasswordPolicyDTO, PasswordPolicySchema)


class PasswordPoliciesAdapter(BaseAdapter[PasswordPolicyService]):
    """Adapter for password policies."""

    _exceptions_map: dict[type[Exception], int] = {
        PasswordPolicyNotFoundError: status.HTTP_404_NOT_FOUND,
        PasswordPolicyAlreadyExistsError: status.HTTP_409_CONFLICT,
    }

    async def get_policy(self) -> PasswordPolicySchema:
        """Get the current password policy."""
        dto = await self._service.get_policy()
        return _convert_dto_to_schema(dto)

    async def update_policy(
        self,
        policy: PasswordPolicySchema,
    ) -> None:
        """Update an existing audit policy."""
        await self._service.update_policy(_convert_schema_to_dto(policy))

    async def reset_policy(
        self,
    ) -> None:
        """Update an existing audit policy."""
        await self._service.reset_policy()

    async def create_policy(
        self,
        policy: PasswordPolicySchema,
    ) -> None:
        """Create current policy setting."""
        await self._service.create_policy(_convert_schema_to_dto(policy))
