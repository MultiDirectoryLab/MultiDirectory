"""Password Policy Use Cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from itertools import islice

from sqlalchemy import Integer, String, cast, update
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.helpers import ft_now
from models import Attribute, User
from password_manager import PasswordValidator

from .dao import PasswordPolicyDAO
from .schema import PasswordPolicySchema
from .validator import PasswordPolicyValidator


class PasswordPolicyUseCases:
    """Password Policy Use Cases."""

    def __init__(
        self,
        password_policy_dao: PasswordPolicyDAO,
        validator: PasswordPolicyValidator,
    ) -> None:
        """Initialize Password Policy Use Cases."""
        self.password_policy_dao = password_policy_dao
        self.validator = validator

    async def get_or_create_pwd_last_set(
        self,
        directory_id: int,
    ) -> str | None:
        """Get pwdLastSet."""
        return await self.password_policy_dao.get_or_create_pwd_last_set(
            directory_id,
        )

    async def get_or_create_password_policy(self) -> "PasswordPolicySchema":
        """Get or create password policy."""
        return await self.password_policy_dao.get_or_create_password_policy()

    async def update_policy(
        self,
        password_policy: PasswordPolicySchema,
    ) -> None:
        """Update Password Policy."""
        await self.password_policy_dao.update_policy(password_policy)

    async def reset_policy(self) -> "PasswordPolicySchema":
        """Reset (delete) default policy."""
        return await self.password_policy_dao.reset_policy()

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
        password_policy: PasswordPolicySchema,
        user: User | None = None,
    ) -> bool:
        """Validate max password change age."""
        if password_policy.max_age_days == 0:
            return False

        if not user:
            return True

        pwd_last_set = (
            await self.password_policy_dao.get_or_create_pwd_last_set(
                user.directory_id,
            )
        )
        password_age_days = PasswordValidator.count_password_age_days(
            pwd_last_set,
        )

        return password_age_days > password_policy.max_age_days

    async def check_password_violations(
        self,
        password: str,
        user: User | None = None,
    ) -> list[str]:
        """Validate password with chosen policy.

        :param PasswordPolicySchema password_policy: Password Policy
        :param str password: new raw password
        :return list[str]: error messages
        """
        password_policy = (
            await self.password_policy_dao.get_or_create_password_policy()
        )

        self.validator.not_otp_like_suffix()

        if user and password_policy.history_length:
            history = islice(
                reversed(user.password_history),
                password_policy.history_length,
            )

            self.validator.reuse_prevention(
                password_history=history,
            )

        if user and password_policy.min_age_days:
            pwd_last_set = (
                await self.password_policy_dao.get_or_create_pwd_last_set(
                    user.directory_id,
                )
            )
            self.validator.min_age(
                password_policy.min_age_days,
                pwd_last_set,
            )

        if password_policy.min_length:
            self.validator.min_length(password_policy.min_length)

        if password_policy.password_must_meet_complexity_requirements:
            self.validator.min_complexity()

        await self.validator.validate(password)
        return self.validator.error_messages
