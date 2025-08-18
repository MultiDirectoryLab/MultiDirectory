"""Adapter for password policies.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Awaitable, Callable, ParamSpec, TypeVar

from fastapi import HTTPException, status

from ldap_protocol.policies.password.dataclasses import (
    PasswordPolicyDTO,
    PasswordPolicyResponse,
)
from ldap_protocol.policies.password.exceptions import (
    PasswordPolicyAlreadyExistsError,
    PasswordPolicyNotFoundError,
)
from ldap_protocol.policies.password.schemas import PasswordPolicySchema
from ldap_protocol.policies.password.service import PasswordPolicyService

P = ParamSpec("P")
R = TypeVar("R")


class PasswordPoliciesAdapter:
    """Adapter for audit policies."""

    def __init__(self, password_policy_service: PasswordPolicyService) -> None:
        """Initialize the adapter with an audit service."""
        self.password_policy_service = password_policy_service

    async def _sc(
        self,
        func: Callable[P, Awaitable[R]],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        """Convert Kerberos exceptions to HTTPException.

        :raises HTTPException: on Kerberos errors
        :return: Result of the function call.
        """
        try:
            return await func(*args, **kwargs)
        except PasswordPolicyNotFoundError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
        except PasswordPolicyAlreadyExistsError:
            raise HTTPException(status.HTTP_409_CONFLICT)

    async def get_policy(self) -> PasswordPolicyResponse:
        """Get the current password policy."""
        policy = await self._sc(
            self.password_policy_service.get_policy,
        )
        return self.get_policy_responce(policy)

    async def update_policy(
        self,
        policy_data: PasswordPolicySchema,
    ) -> None:
        """Update an existing audit policy."""
        policy_dto = PasswordPolicyDTO(**policy_data.model_dump())
        return await self._sc(
            self.password_policy_service.update_policy,
            policy_dto,
        )

    async def reset_policy(
        self,
    ) -> None:
        """Update an existing audit policy."""
        return await self._sc(
            self.password_policy_service.reset_policy,
        )

    async def create_policy(
        self,
        policy: PasswordPolicySchema,
    ) -> None:
        """Create current policy setting."""
        policy_dto = PasswordPolicyDTO(**policy.model_dump())
        return await self._sc(
            self.password_policy_service.create_policy,
            policy_dto,
        )

    def get_policy_responce(
        self,
        policy: PasswordPolicyDTO,
    ) -> PasswordPolicyResponse:
        return PasswordPolicyResponse(
            name=policy.name,
            minimum_password_length=policy.minimum_password_length,
            minimum_password_age_days=policy.minimum_password_age_days,
            maximum_password_age_days=policy.maximum_password_age_days,
            password_history_length=policy.password_history_length,
            password_must_meet_complexity_requirements=policy.password_must_meet_complexity_requirements,
        )
