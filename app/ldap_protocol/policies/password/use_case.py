"""Password Policy Use Cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from itertools import islice

from abstract_dao import AbstractService
from config import Settings
from entities import User

from .dao import PasswordPolicyDAO
from .dataclasses import PasswordPolicyDTO
from .validator import PasswordPolicyValidator


class PasswordPolicyUseCases(AbstractService):
    """Password Policy Use Cases."""

    _pwd_policy_dao: PasswordPolicyDAO
    _password_policy_validator: PasswordPolicyValidator
    _settings: Settings

    def __init__(
        self,
        pwd_policy_dao: PasswordPolicyDAO,
        password_policy_validator: PasswordPolicyValidator,
        settings: Settings,
    ) -> None:
        """Initialize Password Policy Use Cases."""
        self._pwd_policy_dao = pwd_policy_dao
        self._password_policy_validator = password_policy_validator
        self._settings = settings

    async def get_all(self) -> list[PasswordPolicyDTO[int, int]]:
        """Get all Password Policies."""
        return await self._pwd_policy_dao.get_all()

    async def get(self, id_: int) -> PasswordPolicyDTO[int, int]:
        """Get one Password Policy."""
        return await self._pwd_policy_dao.get(id_)

    async def get_result(self, user_path: str) -> PasswordPolicyDTO[int, int]:
        """Get resulting Password Policy for user."""
        return await self._pwd_policy_dao.get_result(user_path)

    async def create(
        self,
        policy_dto: PasswordPolicyDTO[None, int | None],
    ) -> None:
        """Create one Password Policy."""
        await self._pwd_policy_dao.create(policy_dto)

    async def create_default_domain_policy(self) -> None:
        """Create default domain Password Policy with default configuration."""
        await self._pwd_policy_dao.create_default_domain_policy()

    async def update(
        self,
        id_: int,
        password_policy: PasswordPolicyDTO[int, int | None],
    ) -> None:
        """Update one Password Policy."""
        await self._pwd_policy_dao.update(id_, password_policy)

    async def delete(self, id_: int) -> None:
        """Delete one Password Policy."""
        await self._pwd_policy_dao.delete(id_)

    async def reset_domain_policy_to_default_config(self) -> None:
        """Reset domain Password Policy to default configuration."""
        await self._pwd_policy_dao.reset_domain_policy_to_default_config()

    async def update_priorities(
        self,
        new_priorities: dict[int, int],
    ) -> None:
        """Update priority of all Password Policies."""
        await self._pwd_policy_dao.update_priorities(new_priorities)

    async def turnoff(self, id_: int) -> None:
        """Turn off one Password Policy."""
        await self._pwd_policy_dao.turnoff(id_)

    async def get_or_create_pwd_last_set(
        self,
        directory_id: int,
    ) -> str | None:
        """Get or create password last set."""
        return await self._pwd_policy_dao.get_or_create_pwd_last_set(
            directory_id,
        )

    async def get_resulting_password_policy(
        self,
        directory_id: int,
    ) -> PasswordPolicyDTO[int, int]:
        """Get resulting Password Policy for user."""
        return await self._pwd_policy_dao.get_resulting_password_policy(
            directory_id,
        )

    async def post_save_password_actions(self, user: User) -> None:
        """Post save actions for password update."""
        await self._pwd_policy_dao.post_save_password_actions(user)

    async def check_expired_max_age(
        self,
        password_policy: PasswordPolicyDTO[int, int],
        user: User | None = None,
    ) -> bool:
        """Validate max password change age."""
        if password_policy.maximum_password_age_days == 0:
            return False

        if not user:
            return True

        pwd_last_set = await self._pwd_policy_dao.get_or_create_pwd_last_set(
            user.directory_id,
        )
        count_age_days = self._password_policy_validator._password_utils.count_password_age_days(  # noqa: SLF001, E501
            pwd_last_set,
        )

        return bool(count_age_days > password_policy.maximum_password_age_days)

    async def check_password_violations(
        self,
        password: str,
        user: User | None = None,
    ) -> list[str]:
        """Validate password with exist policy.

        :param PasswordPolicyDTO password_policy: Password Policy
        :param str password: new raw password
        :return list[str]: error messages
        """
        if not user:
            password_policy = await self._pwd_policy_dao.get_by_name(
                self._settings.DOMAIN_PASSWORD_POLICY_NAME,
            )
        else:
            password_policy = (
                await self._pwd_policy_dao.get_resulting_password_policy(
                    user.directory_id,
                )
            )

        return await self.validate_password(
            password,
            password_policy,
            user,
        )

    async def validate_password(
        self,
        password: str,
        password_policy: PasswordPolicyDTO,
        user: User | None = None,
    ) -> list[str]:
        """Validate password with given Password Policy."""
        self._password_policy_validator.not_otp_like_suffix()

        if user and password_policy.password_history_length:
            history = islice(
                reversed(user.password_history),
                password_policy.password_history_length,
            )

            self._password_policy_validator.reuse_prevention(
                password_history=history,
            )

        if user and password_policy.minimum_password_age_days:
            pwd_last_set = (
                await self._pwd_policy_dao.get_or_create_pwd_last_set(
                    user.directory_id,
                )
            )
            self._password_policy_validator.min_age(
                password_policy.minimum_password_age_days,
                pwd_last_set,
            )

        if password_policy.minimum_password_length:
            self._password_policy_validator.min_length(
                password_policy.minimum_password_length,
            )

        if password_policy.password_must_meet_complexity_requirements:
            self._password_policy_validator.min_complexity()

        await self._password_policy_validator.validate(password)
        return self._password_policy_validator._error_messages  # noqa: SLF001

    async def is_password_change_restricted(
        self,
        user_directory_id: int,
    ) -> bool:
        """Check if user is restricted from changing password via UAC flag.

        :param int user_directory_id: user's directory ID
        :return bool: True if user is restricted, False otherwise
        """
        return await self._pwd_policy_dao.is_password_change_restricted(
            user_directory_id,
        )
