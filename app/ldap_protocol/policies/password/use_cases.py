"""Password Policy Use Cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from itertools import islice

from abstract_dao import AbstractService
from entities import User

from .dao import PasswordPolicyDAO
from .dataclasses import PasswordPolicyDTO, PriorityT
from .validator import PasswordPolicyValidator


class PasswordPolicyUseCases(AbstractService):
    """Password Policy Use Cases."""

    _password_policy_dao: PasswordPolicyDAO
    _password_policy_validator: PasswordPolicyValidator

    def __init__(
        self,
        password_policy_dao: PasswordPolicyDAO,
        password_policy_validator: PasswordPolicyValidator,
    ) -> None:
        """Initialize Password Policy Use Cases."""
        self._password_policy_dao = password_policy_dao
        self._password_policy_validator = password_policy_validator

    async def get_all(self) -> list[PasswordPolicyDTO[int, int]]:
        """Get all Password Policies."""
        return await self._password_policy_dao.get_all()

    async def get(self, id_: int) -> PasswordPolicyDTO[int, int]:
        """Get one Password Policy."""
        return await self._password_policy_dao.get(id_)

    async def get_password_policy_by_dir_path_dn(
        self,
        path_dn: str,
    ) -> PasswordPolicyDTO[int, int]:
        """Get one Password Policy for one Directory by its path."""
        return (
            await self._password_policy_dao.get_password_policy_by_dir_path_dn(
                path_dn,
            )
        )

    async def create(self, dto: PasswordPolicyDTO[None, PriorityT]) -> None:
        """Create one Password Policy."""
        await self._password_policy_dao.create(dto)

    async def create_default_domain_policy(self) -> None:
        """Create default domain Password Policy with default configuration."""
        await self._password_policy_dao.create_default_domain_policy()

    async def update(
        self,
        id_: int,
        dto: PasswordPolicyDTO[int, PriorityT],
    ) -> None:
        """Update one Password Policy."""
        await self._password_policy_dao.update(id_, dto)

    async def reset_domain_policy_to_default_config(self) -> None:
        """Reset domain Password Policy to default configuration."""
        await self._password_policy_dao.reset_domain_policy_to_default_config()

    async def turnoff(self, id_: int) -> None:
        """Turn off one Password Policy."""
        await self._password_policy_dao.turnoff(id_)

    async def get_or_create_pwd_last_set(
        self,
        directory_id: int,
    ) -> str | None:
        """Get or create password last set."""
        return await self._password_policy_dao.get_or_create_pwd_last_set(
            directory_id,
        )

    async def get_password_policy_for_user(
        self,
        user: User,
    ) -> PasswordPolicyDTO[int, int]:
        """Get resulting Password Policy for user."""
        return await self._password_policy_dao.get_password_policy_for_user(
            user,
        )

    async def get_max_age_days_for_user(self, user: User) -> int:
        """Get max age days from Password Policy for user."""
        return await self._password_policy_dao.get_max_age_days_for_user(
            user,
        )

    async def post_save_password_actions(self, user: User) -> None:
        """Post save actions for password update."""
        await self._password_policy_dao.post_save_password_actions(user)

    async def check_expired_max_age(
        self,
        user: User | None = None,
        pwd_last_set: str | None = None,
    ) -> bool:
        """Validate max password change age."""
        if not user:
            return True

        pwd_policy_max_age = (
            await self._password_policy_dao.get_max_age_days_for_user(
                user,
            )
        )
        if pwd_policy_max_age == 0:
            return False

        count_age_days = self._password_policy_validator._password_validator.count_password_age_days(  # noqa: SLF001, E501
            pwd_last_set,
        )

        return bool(count_age_days > pwd_policy_max_age)

    async def check_password_violations(
        self,
        password: str,
        user: User | None,
    ) -> list[str]:
        """Validate password with exist policy.

        :param PasswordPolicyDTO password_policy: Password Policy
        :param str password: new raw password
        :return list[str]: error messages
        """
        if user:
            password_policy = (
                await self._password_policy_dao.get_password_policy_for_user(
                    user,
                )
            )
        else:
            password_policy = (
                await self._password_policy_dao.get_domain_password_policy()
            )

        return await self.validate_password(
            password,
            password_policy,
            user,
        )

    async def validate_password(
        self,
        password: str,
        pwd_policy_dto: PasswordPolicyDTO,
        user: User | None = None,
    ) -> list[str]:
        """Validate password with given Password Policy."""
        self._password_policy_validator.not_otp_like_suffix()

        if user and pwd_policy_dto.history_length:
            history = islice(
                reversed(user.password_history),
                pwd_policy_dto.history_length,
            )

            self._password_policy_validator.reuse_prevention(
                password_history=history,
            )

        if user and pwd_policy_dto.min_age_days:
            pwd_last_set = (
                await self._password_policy_dao.get_or_create_pwd_last_set(
                    user.directory_id,
                )
            )
            self._password_policy_validator.min_age(
                pwd_policy_dto.min_age_days,
                pwd_last_set,
            )

        if pwd_policy_dto.min_length:
            self._password_policy_validator.min_length(
                pwd_policy_dto.min_length,
            )

        if pwd_policy_dto.password_must_meet_complexity_requirements:
            self._password_policy_validator.min_complexity()

        await self._password_policy_validator.validate(password)
        return self._password_policy_validator.error_messages

    async def is_password_change_restricted(
        self,
        user_directory_id: int,
    ) -> bool:
        """Check if user is restricted from changing password via UAC flag.

        :param int user_directory_id: user's directory ID
        :return bool: True if user is restricted, False otherwise
        """
        return await self._password_policy_dao.is_password_change_restricted(
            user_directory_id,
        )
