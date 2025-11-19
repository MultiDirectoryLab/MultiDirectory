"""Conftest for testing Password Policy router.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncIterator
from unittest.mock import AsyncMock, Mock

import pytest_asyncio
from dishka import (
    AsyncContainer,
    Provider,
    Scope,
    make_async_container,
    provide,
)

from api.password_policy.adapter import PasswordPolicyFastAPIAdapter
from config import Settings
from ldap_protocol.policies.password import PasswordPolicyUseCases
from ldap_protocol.policies.password.dataclasses import PasswordPolicyDTO
from tests.conftest import TestProvider


class TestLocalProvider(Provider):
    """Test provider for local scope."""

    _cached_password_use_cases: Mock | None = None

    password_policies_adapter = provide(
        PasswordPolicyFastAPIAdapter,
        scope=Scope.REQUEST,
    )

    @provide(scope=Scope.REQUEST, provides=PasswordPolicyUseCases)
    async def get_password_use_cases(self) -> AsyncIterator[AsyncMock]:
        """Provide a mock password policy use cases."""
        if not self._cached_password_use_cases:
            password_use_cases = Mock()

            dto = PasswordPolicyDTO(
                id=1,
                group_paths=["dc=md,dc=test"],
                name="Test pwd Policy",
                language="Latin",
                priority=1,
                is_exact_match=True,
                history_length=10,
                min_age_days=7,
                max_age_days=30,
                min_length=8,
                max_length=32,
                min_lowercase_letters_count=0,
                min_uppercase_letters_count=0,
                min_special_symbols_count=0,
                min_digits_count=0,
                min_unique_symbols_count=0,
                max_repeating_symbols_in_row_count=0,
                max_sequential_keyboard_symbols_count=0,
                max_sequential_alphabet_symbols_count=0,
                max_failed_attempts=6,
                failed_attempts_reset_sec=60,
                lockout_duration_sec=600,
                fail_delay_sec=5,
            )
            password_use_cases.get_all = AsyncMock(return_value=[dto])
            password_use_cases.get = AsyncMock(return_value=dto)
            password_use_cases.get_password_policy_by_dir_path_dn = AsyncMock(
                return_value=dto,
            )
            password_use_cases.create = AsyncMock(return_value=None)
            password_use_cases.create_default_domain_policy = AsyncMock(
                return_value=None,
            )
            password_use_cases.update = AsyncMock(return_value=None)
            password_use_cases.delete = AsyncMock(return_value=None)
            password_use_cases.reset_domain_policy_to_default_config = (
                AsyncMock(
                    return_value=None,
                )
            )
            password_use_cases.update_priorities = AsyncMock(
                return_value=None,
            )
            password_use_cases.get_or_create_pwd_last_set = AsyncMock(
                return_value=None,
            )
            password_use_cases.get_password_policy_for_user = AsyncMock(
                return_value=dto,
            )
            password_use_cases.post_save_password_actions = AsyncMock(
                return_value=None,
            )
            password_use_cases.check_expired_max_age = AsyncMock(
                return_value=True,
            )
            password_use_cases.check_password_violations = AsyncMock(
                return_value=[],
            )
            password_use_cases.validate_password = AsyncMock(
                return_value=[],
            )
            password_use_cases.is_password_change_restricted = AsyncMock(
                return_value=True,
            )
            self._cached_password_use_cases = password_use_cases

        yield self._cached_password_use_cases

        self._cached_password_use_cases = None


@pytest_asyncio.fixture(scope="session")
async def container(settings: Settings) -> AsyncIterator[AsyncContainer]:
    """Fixture to provide the test container."""
    container = make_async_container(
        TestProvider(),
        TestLocalProvider(),
        context={Settings: settings},
        start_scope=Scope.RUNTIME,
    )
    yield container
    await container.close()


@pytest_asyncio.fixture
async def password_use_cases(
    container: AsyncContainer,
) -> AsyncIterator[PasswordPolicyUseCases]:
    """Get di password_use_cases."""
    async with container(scope=Scope.REQUEST) as container:
        yield await container.get(PasswordPolicyUseCases)
