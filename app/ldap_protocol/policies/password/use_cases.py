"""Password Policy Use Cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from itertools import islice

from sqlalchemy import Integer, String, cast, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.password_policy.schemas import PasswordPolicySchema
from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.helpers import ft_now
from models import Attribute, User

from .dataclasses import PasswordPolicyDTO
from .policies_dao import PasswordPolicyDAO
from .validator import PasswordPolicyValidator


class PasswordPolicyUseCases:
    """Password Policy Use Cases."""

    def __init__(
        self,
        password_policy_dao: PasswordPolicyDAO,
        policy_validator: PasswordPolicyValidator,
    ) -> None:
        """Initialize Password Policy Use Cases."""
        self.password_policy_dao = password_policy_dao
        self.policy_validator = policy_validator

    async def get_or_create_pwd_last_set(
        self,
        directory_id: int,
    ) -> str | None:
        """Get pwdLastSet."""
        return await self.password_policy_dao.get_or_create_pwd_last_set(
            directory_id,
        )

    async def get_password_policy(self) -> "PasswordPolicyDTO":
        """Get or create password policy."""
        return await self.password_policy_dao.get()

    async def create_policy(self) -> None:
        policy_dto = self.get_default_settings()
        await self.password_policy_dao.create(policy_dto)

    async def update_policy(
        self,
        password_policy: PasswordPolicySchema,
    ) -> None:
        """Update Password Policy."""
        policy_dto = PasswordPolicyDTO(
            **password_policy.model_dump(),
        )
        await self.password_policy_dao.update(policy_dto)

    async def reset_policy(self) -> None:
        """Reset (delete) default policy."""
        await self.password_policy_dao.delete()

    @staticmethod
    async def post_save_password_actions(
        user: User,
        session: AsyncSession,
    ) -> None:
        """Post save actions for password update.

        :param User user: user from db
        :param AsyncSession session: db
        """
        await session.execute(  # update bind reject attribute
            update(Attribute)
            .values({"value": ft_now()})
            .filter_by(directory_id=user.directory_id, name="pwdLastSet"),
        )

        new_value = cast(
            cast(Attribute.value, Integer).op("&")(
                ~UserAccountControlFlag.PASSWORD_EXPIRED,
            ),
            String,
        )
        query = (
            update(Attribute)
            .values(value=new_value)
            .filter_by(
                directory_id=user.directory_id,
                name="userAccountControl",
            )
        )
        await session.execute(query)

        user.password_history.append(user.password)
        await session.flush()

    async def check_expired_max_age(
        self,
        password_policy: PasswordPolicyDTO,
        user: User | None = None,
    ) -> bool:
        """Validate max password change age."""
        if password_policy.maximum_password_age_days == 0:
            return False

        if not user:
            return True

        pwd_last_set = (
            await self.password_policy_dao.get_or_create_pwd_last_set(
                user.directory_id,
            )
        )
        password_age_days = (
            self.policy_validator.password_validator.count_password_age_days(
                pwd_last_set,
            )
        )

        return password_age_days > password_policy.maximum_password_age_days

    def get_default_settings(self) -> PasswordPolicyDTO:
        """Get default password policy settings."""
        return self.password_policy_dao.get_default_policy()

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
        password_policy = await self.password_policy_dao.get()
        return await self.validate_password(
            password,
            password_policy,
            user,
        )

    async def check_default_policy_password_violations(
        self,
        password: str,
        user: User | None = None,
    ) -> list[str]:
        password_policy = self.get_default_settings()
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
        self.policy_validator.not_otp_like_suffix()

        if user and password_policy.password_history_length:
            history = islice(
                reversed(user.password_history),
                password_policy.password_history_length,
            )

            self.policy_validator.reuse_prevention(
                password_history=history,
            )

        if user and password_policy.minimum_password_age_days:
            pwd_last_set = (
                await self.password_policy_dao.get_or_create_pwd_last_set(
                    user.directory_id,
                )
            )
            self.policy_validator.min_age(
                password_policy.minimum_password_age_days,
                pwd_last_set,
            )

        if password_policy.minimum_password_length:
            self.policy_validator.min_length(
                password_policy.minimum_password_length,
            )

        if password_policy.password_must_meet_complexity_requirements:
            self.policy_validator.min_complexity()

        await self.policy_validator.validate(password)
        return self.policy_validator.error_messages
