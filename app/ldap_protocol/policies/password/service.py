"""Password  policies service module.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abstract_dao import AbstractService

from .dataclasses import PasswordPolicyDTO
from .policies_dao import PasswordPolicyDAO


class PasswordPolicyService(AbstractService):
    """Password policy service class for managing password policies."""

    def __init__(
        self,
        policy_dao: PasswordPolicyDAO,
    ) -> None:
        """Initialize PasswordPolicyService with a policy DAO."""
        self._policy_dao = policy_dao

    async def get_policy(self) -> PasswordPolicyDTO:
        """Get the current password policy."""
        return await self._policy_dao.get()

    async def update_policy(
        self,
        policy_dto: PasswordPolicyDTO,
    ) -> None:
        """Update an existing password policy.

        :param PasswordPolicyDTO policy_dto: The new policy data.
        """
        await self._policy_dao.update(policy_dto)

    async def reset_policy(
        self,
    ) -> None:
        """Delete an existing password policy."""
        await self._policy_dao.delete()

    async def create_policy(
        self,
        policy_dto: PasswordPolicyDTO,
    ) -> None:
        """Create a new password policy.

        :param PasswordPolicyDTO policy_dto: The policy data to create.
        """
        await self._policy_dao.create(policy_dto)
