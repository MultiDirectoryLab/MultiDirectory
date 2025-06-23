"""Password policies tools and CRUD.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Self

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import Integer, String, cast, exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.user_account_control import UserAccountControlFlag
from ldap_protocol.utils.helpers import ft_now
from models import Attribute, PasswordPolicy, User
from password_validator.validator import PasswordValidator
from security import count_password_age_days


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
        .filter_by(directory_id=user.directory_id, name="userAccountControl")
    )
    await session.execute(query)

    user.password_history.append(user.password)


class PasswordPolicySchema(BaseModel):
    """Password Policy schema."""

    name: str = Field(
        "Default domain password policy",
        min_length=3,
        max_length=255,
    )

    history_length: int = Field(4, ge=0, le=24)

    min_age_days: int = Field(0, ge=0, le=999)
    max_age_days: int = Field(0, ge=0, le=999)

    min_length: int = Field(7, ge=6, le=32)
    max_length: int = Field(32, ge=8, le=256)

    min_lowercase_letters_count: int = Field(0, ge=0, le=256)
    min_uppercase_letters_count: int = Field(0, ge=0, le=256)
    min_letters_count: int = Field(0, ge=0, le=256)

    min_special_symbols_count: int = Field(0, ge=0, le=256)
    min_digits_count: int = Field(0, ge=0, le=256)
    min_unique_symbols_count: int = Field(0, ge=0, le=256)
    max_repeating_symbols_in_row_count: int = Field(0, ge=0, le=8)

    max_sequential_keyboard_symbols_count: int = Field(0, ge=0, le=8)
    max_sequential_alphabet_symbols_count: int = Field(0, ge=0, le=8)

    @model_validator(mode="after")
    def _validate_minimum_pwd_age(self) -> Self:
        if self.min_age_days > self.max_age_days:
            raise ValueError(
                "Minimum password age days must be "
                "less or equal than maximum password age days"
            )
        return self

    @model_validator(mode="after")
    def _validate_minimum_pwd_length(self) -> Self:
        if self.min_length > self.max_length:
            raise ValueError(
                "Minimum password length must be "
                "less or equal than maximum password length"
            )
        return self

    @model_validator(mode="after")
    def _validate_max_length(self) -> Self:
        if (
            self.min_lowercase_letters_count
            + self.min_uppercase_letters_count
            + self.min_letters_count
            + self.min_special_symbols_count
            + self.min_digits_count
        ) > self.max_length:
            raise ValueError(
                "Sum of required characters must be "
                "less or equal than the maximum password length."
            )
        return self

    @model_validator(mode="after")
    def _validate_min_letters_count(self) -> Self:
        if (
            self.min_lowercase_letters_count + self.min_uppercase_letters_count
        ) > self.min_letters_count:
            raise ValueError(
                "Sum of lowercase and uppercase letters must be "
                "less or equal than the maximum letters count."
            )
        return self

    @model_validator(mode="after")
    def _validate_max_repeating_symbols_in_row_count(self) -> Self:
        if 0 < self.max_repeating_symbols_in_row_count < 2:
            raise ValueError(
                "Repeating symbols in row count must be "
                "greater than 1 or equal 0."
            )
        return self

    @model_validator(mode="after")
    def _validate_max_sequential_keyboard_symbols_count(self) -> Self:
        if 0 < self.max_sequential_keyboard_symbols_count < 3:
            raise ValueError(
                "Max sequential keyboard symbols count must be "
                "greater than 2 or equal 0."
            )

        if self.max_sequential_keyboard_symbols_count > self.min_length:
            raise ValueError(
                "Max sequential keyboard symbols count must be "
                "less than or equal to the minimum password length."
            )

        return self

    @model_validator(mode="after")
    def _validate_max_sequential_alphabet_symbols_count(self) -> Self:
        if 0 < self.max_sequential_alphabet_symbols_count < 3:
            raise ValueError(
                "Max sequential alphabet symbols count must be "
                "greater than 2 or equal 0."
            )

        if self.max_sequential_alphabet_symbols_count > self.min_length:
            raise ValueError(
                "Max sequential alphabet symbols count must be "
                "less than or equal to the minimum password length."
            )

        return self


class PasswordPolicyDAO:
    """Password Policy DAO."""

    _session: AsyncSession
    _user: User | None

    def __init__(self, session: AsyncSession, user: User | None = None):
        """Initialize Password Policy DAO with a database session."""
        self._session = session
        self._user = user

    async def update_policy(
        self,
        password_policy: PasswordPolicySchema,
    ) -> None:
        """Update Password Policy."""
        await self._session.execute(
            update(PasswordPolicy).values(
                password_policy.model_dump(mode="json")
            )
        )
        await self._session.commit()

    async def reset_policy(self) -> "PasswordPolicySchema":
        """Reset (delete) default policy."""
        default_policy = PasswordPolicySchema()
        await self.update_policy(default_policy)
        return default_policy

    async def create_policy(
        self,
        password_policy_schema: PasswordPolicySchema,
    ) -> "PasswordPolicySchema":
        """Create policies settings."""
        existing_policy = await self._session.scalar(
            select(exists(PasswordPolicy))
        )
        if existing_policy:
            raise PermissionError("Policy already exists")

        self._session.add(
            PasswordPolicy(**password_policy_schema.model_dump(mode="json"))
        )
        await self._session.flush()

        return password_policy_schema

    async def get_ensure_policy(self) -> "PasswordPolicySchema":
        """Get ensure password policy."""
        password_policy = await self._session.scalar(select(PasswordPolicy))

        if not password_policy:
            password_policy_schema = PasswordPolicySchema()
            return await self.create_policy(password_policy_schema)

        return PasswordPolicySchema.model_validate(
            password_policy,
            from_attributes=True,
        )

    async def get_ensure_pwd_last_set(
        self,
        directory_id: int,
    ) -> str | None:
        """Get pwdLastSet."""
        plset_attribute = await self._session.scalar(
            select(Attribute)
            .where(
                Attribute.directory_id == directory_id,
                Attribute.name == "pwdLastSet",
            ),
        )  # fmt: skip

        if not plset_attribute:
            plset_attribute = Attribute(
                directory_id=directory_id,
                name="pwdLastSet",
                value=ft_now(),
            )

            self._session.add(plset_attribute)
            await self._session.commit()

        return plset_attribute.value

    async def check_expired_max_age(
        self,
        password_policy: PasswordPolicySchema,
    ) -> bool:
        """Validate max password change age."""
        if password_policy.max_age_days == 0:
            return False

        if not self._user:
            return True

        pwd_last_set = await self.get_ensure_pwd_last_set(
            self._user.directory_id
        )
        password_age_days = count_password_age_days(pwd_last_set)

        return password_age_days > password_policy.max_age_days

    async def check_password_violations(
        self,
        password_policy: PasswordPolicySchema,
        password: str,
    ) -> list[str]:
        """Validate password with chosen policy.

        :param PasswordPolicySchema password_policy: Password Policy
        :param str password: new raw password
        :return list[str]: error messages
        """
        schema = PasswordValidator()

        schema.not_otp_like_suffix()
        schema.not_contains_in_common_list(self._session)
        schema.not_contain_ban_word(self._session)

        if password_policy.history_length and self._user:
            schema.reuse_prevention(
                password_history=self._user.password_history,
                history_slice_size=password_policy.history_length,
            )

        if password_policy.min_age_days and self._user:
            pwd_last_set = await self.get_ensure_pwd_last_set(
                self._user.directory_id
            )
            schema.min_age(
                password_policy.min_age_days,
                pwd_last_set,
            )

        if password_policy.min_length:
            schema.min_length(password_policy.min_length)

        if password_policy.max_length:
            schema.max_length(password_policy.max_length)

        if password_policy.min_lowercase_letters_count:
            schema.min_lowercase_letters_count(
                password_policy.min_lowercase_letters_count
            )

        if password_policy.min_uppercase_letters_count:
            schema.min_uppercase_letters_count(
                password_policy.min_uppercase_letters_count
            )

        if password_policy.min_letters_count:
            schema.min_letters_count(password_policy.min_letters_count)

        if password_policy.min_special_symbols_count:
            schema.min_special_symbols_count(
                password_policy.min_special_symbols_count
            )

        if password_policy.min_digits_count:
            schema.min_digits_count(password_policy.min_digits_count)

        if password_policy.min_unique_symbols_count:
            schema.min_unique_symbols_count(
                password_policy.min_unique_symbols_count
            )

        if password_policy.max_repeating_symbols_in_row_count:
            schema.max_repeating_symbols_in_row_count(
                password_policy.max_repeating_symbols_in_row_count,
            )

        if password_policy.max_sequential_keyboard_symbols_count:
            schema.max_sequential_keyboard_symbols_count(
                password_policy.max_sequential_keyboard_symbols_count,
            )

        if password_policy.max_sequential_alphabet_symbols_count:
            schema.max_sequential_alphabet_symbols_count(
                password_policy.max_sequential_alphabet_symbols_count,
            )

        await schema.validate(password)
        return schema.error_messages
