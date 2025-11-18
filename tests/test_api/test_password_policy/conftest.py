"""Conftest for testing Password Policy router.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Any, AsyncIterator
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


def make_mock(name: str, return_val: Any = None) -> AsyncMock:
    """Make mock object."""
    mock = AsyncMock(name=name, return_value=return_val)
    mock.__name__ = name

    return mock


class TestLocalProvider(Provider):
    """Test provider for local scope."""

    _cached_policy_use_cases: PasswordPolicyUseCases | None = None

    password_policies_adapter = provide(
        PasswordPolicyFastAPIAdapter,
        scope=Scope.REQUEST,
    )

    @provide(scope=Scope.REQUEST, provides=PasswordPolicyUseCases)
    async def get_password_use_cases(
        self,
    ) -> AsyncIterator[PasswordPolicyUseCases]:
        if self._cached_policy_use_cases is None:
            dto = PasswordPolicyDTO(
                id=1,
                group_paths=["dc=md,dc=test"],
                name="Test pwd Policy",
                priority=1,
                history_length=10,
                min_age_days=7,
                max_age_days=30,
                min_length=8,
                password_must_meet_complexity_requirements=True,
            )
            password_policy_dao = Mock()
            password_policy_validator = Mock()

            use_cases = PasswordPolicyUseCases(
                password_policy_dao,
                password_policy_validator,
            )
            use_cases.get_all = make_mock("get_all", [dto])  # type: ignore
            use_cases.get = make_mock("get", dto)  # type: ignore
            use_cases.get_password_policy_by_dir_path_dn = make_mock(  # type: ignore
                "get_password_policy_by_dir_path_dn",
                dto,
            )
            use_cases.create = make_mock("create")  # type: ignore
            use_cases.create_default_domain_policy = make_mock(  # type: ignore
                "create_default_domain_policy",
            )
            use_cases.update = make_mock("update")  # type: ignore
            use_cases.reset_domain_policy_to_default_config = make_mock(  # type: ignore
                "reset_domain_policy_to_default_config",
            )
            use_cases.turnoff = make_mock("turnoff")  # type: ignore
            use_cases.get_password_policy_for_user = make_mock(  # type: ignore
                "get_password_policy_for_user",
                dto,
            )
            use_cases.post_save_password_actions = make_mock(  # type: ignore
                "post_save_password_actions",
            )
            use_cases.check_expired_max_age = make_mock(  # type: ignore
                "check_expired_max_age",
                True,
            )
            use_cases.check_password_violations = make_mock(  # type: ignore
                "check_password_violations",
                [],
            )
            use_cases.validate_password = make_mock("validate_password", [])  # type: ignore
            use_cases.is_password_change_restricted = make_mock(  # type: ignore
                "is_password_change_restricted",
                True,
            )

            self._cached_policy_use_cases = use_cases

        yield self._cached_policy_use_cases
        self._cached_policy_use_cases = None


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
