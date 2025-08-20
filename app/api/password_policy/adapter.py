"""Adapter for password policies.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import ParamSpec, TypeVar

from fastapi import status

from api.base_adapter import BaseAdapter
from api.password_policy.schemas import (
    PasswordPolicyResponseDTO,
    PasswordPolicySchema,
)
from ldap_protocol.policies.password.dataclasses import PasswordPolicyDTO
from ldap_protocol.policies.password.exceptions import (
    PasswordPolicyAlreadyExistsError,
    PasswordPolicyNotFoundError,
)
from ldap_protocol.policies.password.service import PasswordPolicyService

P = ParamSpec("P")
R = TypeVar("R")


class PasswordPoliciesAdapter(BaseAdapter[PasswordPolicyService]):
    """Adapter for password policies."""

    _exceptions_map: dict[type[Exception], int] = {
        PasswordPolicyNotFoundError: status.HTTP_404_NOT_FOUND,
        PasswordPolicyAlreadyExistsError: status.HTTP_409_CONFLICT,
    }

    def get_policy_response(
        self,
        policy: PasswordPolicyDTO,
    ) -> PasswordPolicyResponseDTO:
        return PasswordPolicyResponseDTO(
            name=policy.name,
            minimum_password_length=policy.minimum_password_length,
            minimum_password_age_days=policy.minimum_password_age_days,
            maximum_password_age_days=policy.maximum_password_age_days,
            password_history_length=policy.password_history_length,
            password_must_meet_complexity_requirements=policy.password_must_meet_complexity_requirements,
        )

    async def get_policy(self) -> PasswordPolicyResponseDTO:
        """Get the current password policy."""
        policy = await self._service.get_policy()
        return self.get_policy_response(policy)

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
        policy_dto = PasswordPolicyDTO(**policy.model_dump())
        return await self._service.create_policy(policy_dto)
