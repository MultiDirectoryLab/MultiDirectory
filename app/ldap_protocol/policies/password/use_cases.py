"""Password Policy Use Cases.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Iterable

from abstract_dao import AbstractService
from entities import User
from ldap_protocol.policies.password.ban_word_repository import (
    PasswordBanWordRepository,
)
from ldap_protocol.policies.password.constants import (
    MAX_BANWORD_LENGTH,
    MIN_LENGTH_FOR_TRGM,
)

from .dao import PasswordPolicyDAO
from .dataclasses import PasswordPolicyDTO, PriorityT
from .validator import PasswordPolicyValidator


class PasswordPolicyUseCases(AbstractService):
    """Password Policy Use Cases."""

    _password_policy_dao: PasswordPolicyDAO
    _password_policy_validator: PasswordPolicyValidator
    _password_ban_word_repository: PasswordBanWordRepository

    def __init__(
        self,
        password_policy_dao: PasswordPolicyDAO,
        password_policy_validator: PasswordPolicyValidator,
        password_ban_word_repository: PasswordBanWordRepository,
    ) -> None:
        """Initialize Password Policy Use Cases."""
        self._password_policy_dao = password_policy_dao
        self._password_policy_validator = password_policy_validator
        self._password_ban_word_repository = password_ban_word_repository

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

        self._password_policy_validator.setup_language(
            password_policy.language,
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
        """Validate password with chosen policy.

        :param PasswordPolicyDTO password_policy: Password Policy
        :param str password: new raw password
        :return list[str]: error messages
        """
        self._password_policy_validator.language()
        self._password_policy_validator.not_otp_like_suffix()

        if password_policy.is_exact_match:
            self._password_policy_validator.not_equal_any_ban_word(
                self._password_ban_word_repository,
            )
        else:
            self._password_policy_validator.not_contain_any_ban_word(
                self._password_ban_word_repository,
            )

        if user and password_policy.history_length:
            self._password_policy_validator.reuse_prevention(
                password_history=user.password_history,
            )

        if user and password_policy.min_age_days:
            pwd_last_set = (
                await self._password_policy_dao.get_or_create_pwd_last_set(
                    user.directory_id,
                )
            )
            self._password_policy_validator.min_age(
                password_policy.min_age_days,
                pwd_last_set,
            )

        password_min_length = password_policy.min_length or MIN_LENGTH_FOR_TRGM
        self._password_policy_validator.min_length(password_min_length)
        if password_policy.max_length:
            self._password_policy_validator.max_length(
                password_policy.max_length,
            )

        if password_policy.min_lowercase_letters_count:
            self._password_policy_validator.min_lowercase_letters_count(
                password_policy.min_lowercase_letters_count,
            )

        if password_policy.min_uppercase_letters_count:
            self._password_policy_validator.min_uppercase_letters_count(
                password_policy.min_uppercase_letters_count,
            )

        if (
            password_policy.min_lowercase_letters_count
            and password_policy.min_uppercase_letters_count
        ):
            self._password_policy_validator.min_letters_count(
                password_policy.min_lowercase_letters_count
                + password_policy.min_uppercase_letters_count,
            )

        if password_policy.min_special_symbols_count:
            self._password_policy_validator.min_special_symbols_count(
                password_policy.min_special_symbols_count,
            )

        if password_policy.min_digits_count:
            self._password_policy_validator.min_digits_count(
                password_policy.min_digits_count,
            )

        if password_policy.min_unique_symbols_count:
            self._password_policy_validator.min_unique_symbols_count(
                password_policy.min_unique_symbols_count,
            )

        if password_policy.max_repeating_symbols_in_row_count:
            self._password_policy_validator.max_repeating_symbols_in_row_count(
                password_policy.max_repeating_symbols_in_row_count,
            )

        if password_policy.max_sequential_keyboard_symbols_count:
            self._password_policy_validator.max_sequential_keyboard_symbols_count(
                password_policy.max_sequential_keyboard_symbols_count,
            )

        if password_policy.max_sequential_alphabet_symbols_count:
            self._password_policy_validator.max_sequential_alphabet_symbols_count(
                password_policy.max_sequential_alphabet_symbols_count,
            )

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

    async def is_required_password_change(self, user: User) -> bool:
        """Check if user is required to change password.

        :param User user: user
        :return bool: required or not
        """
        pwd_last_set = (
            await self._password_policy_dao.get_or_create_pwd_last_set(
                user.directory_id,
            )
        )
        is_pwd_expired = await self.check_expired_max_age(
            user,
            pwd_last_set,
        )

        return bool(pwd_last_set == "0" or is_pwd_expired)  # noqa: S105


class PasswordBanWordUseCases(AbstractService):
    """Password Ban Word Use Cases."""

    def __init__(
        self,
        password_ban_word_repository: PasswordBanWordRepository,
    ) -> None:
        """Initialize Password Ban Word Use Cases."""
        self.password_ban_word_repository = password_ban_word_repository

    async def get_all(self) -> Iterable[str]:
        """Get all Password Ban Words."""
        return await self.password_ban_word_repository.get_all()

    async def replace_all_ban_words(
        self,
        ban_words: Iterable[str],
    ) -> None:
        """Replace all Password Ban Words."""
        await self.password_ban_word_repository.replace(ban_words)

    def filter_ban_words(self, lines: list[str]) -> list[str]:
        res = []
        for line in lines:
            new_word = line.strip()
            if (
                new_word
                and MIN_LENGTH_FOR_TRGM <= len(new_word) <= MAX_BANWORD_LENGTH
            ):
                res.append(new_word)

        return res
