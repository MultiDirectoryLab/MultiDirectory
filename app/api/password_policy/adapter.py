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

_convert = get_converter(PasswordPolicySchema, PasswordPolicyDTO)


class PasswordPoliciesAdapter(BaseAdapter[PasswordPolicyService]):
    """Adapter for password policies."""

    _exceptions_map: dict[type[Exception], int] = {
        PasswordPolicyNotFoundError: status.HTTP_404_NOT_FOUND,
        PasswordPolicyAlreadyExistsError: status.HTTP_409_CONFLICT,
    }

    async def get_policy(self) -> PasswordPolicyDTO:
        """Get the current password policy."""
        return await self._service.get_policy()

    async def update_policy(
        self,
        policy_data: PasswordPolicySchema,
    ) -> None:
        """Update an existing audit policy."""
        policy_dto = PasswordPolicyDTO(**policy_data.model_dump())
        return await self._service.update_policy(policy_dto)

    async def reset_policy(
        self,
    ) -> None:
        """Update an existing audit policy."""
        return await self._service.reset_policy()

    async def create_policy(
        self,
        policy: PasswordPolicySchema,
    ) -> None:
        """Create current policy setting."""
        return await self._service.create_policy(_convert(policy))
