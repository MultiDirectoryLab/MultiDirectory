"""Create network policies and users for shadow api tests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import inspect
from typing import Any, AsyncGenerator, AsyncIterator, Callable, Literal
from unittest.mock import Mock

import pytest_asyncio
from dishka import (
    AsyncContainer,
    Provider,
    Scope,
    make_async_container,
    provide,
)

from abstract_service import AbstractService
from authorization_provider_protocol import AuthorizationProviderProtocol
from config import Settings
from ldap_protocol.auth.auth_manager import AuthManager
from ldap_protocol.dhcp.base import AbstractDHCPManager
from ldap_protocol.dhcp.stub import StubDHCPManager
from ldap_protocol.policies.audit.service import AuditService
from tests.conftest import TestProvider


class TestLocalProvider(Provider):
    """Test provider for local scope."""

    __test__ = False

    scope = Scope.REQUEST
    audit_destination_dao = provide(AuditService, scope=Scope.REQUEST)

    @provide(scope=Scope.REQUEST)
    async def abstract_dhcp_manager(
        self,
    ) -> AsyncIterator[AbstractDHCPManager]:
        """Provide a mock DHCP manager."""
        manager = StubDHCPManager(
            kea_dhcp_repository=Mock(),
            dhcp_manager_repository=Mock(),
        )
        yield manager


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


def create_mock_arg(param_type: Any) -> Any | Literal[1] | Literal["test"]:
    """Create a mock argument based on type."""
    if param_type is int:
        return 1
    elif param_type is str:
        return "test"
    else:
        mock = Mock()
        mock.id = 1
        return mock


def get_params(method: Callable) -> tuple[list, dict]:
    """Get params for test method."""
    sig = inspect.signature(method)
    params = [p for p in sig.parameters.values() if p.name != "self"]
    args = [
        create_mock_arg(p.annotation)
        for p in params
        if p.default == inspect.Parameter.empty
    ]
    kwargs = {
        p.name: create_mock_arg(p.annotation)
        for p in params
        if p.default != inspect.Parameter.empty
    }

    return (args, kwargs)


async def get_test_instance(
    container: AsyncContainer,
    request_params: dict,
    cls: type[AbstractService],
    api_permissions_checker: AuthorizationProviderProtocol,
) -> AbstractService:
    """Make service instance for test."""
    async with container(
        scope=Scope.REQUEST,
        context=request_params,
    ) as cont:
        cls_instance = await cont.get(cls)

    cls_instance.set_permissions_checker(api_permissions_checker)
    if cls == AuthManager:
        cls_instance._monitor.wrap_login = lambda x: x  # noqa: SLF001
        cls_instance._monitor.wrap_reset_password = lambda x: x  # noqa: SLF001
        cls_instance._monitor.wrap_change_password = lambda x: x  # noqa: SLF001

    return cls_instance


async def get_test_instance_generator(
    container: AsyncContainer,
    request_params: dict,
    api_permissions_checker: AuthorizationProviderProtocol,
) -> AsyncGenerator[AbstractService, None]:
    """Make service instance for tests."""
    subclasses = AbstractService.__subclasses__()
    for cls in subclasses:
        async with container(
            scope=Scope.REQUEST,
            context=request_params,
        ) as cont:
            cls_instance = await cont.get(cls)

        cls_instance.set_permissions_checker(api_permissions_checker)
        if cls == AuthManager:
            cls_instance._monitor.wrap_login = lambda x: x  # noqa: SLF001
            cls_instance._monitor.wrap_reset_password = lambda x: x  # noqa: SLF001
            cls_instance._monitor.wrap_change_password = lambda x: x  # noqa: SLF001

        yield cls_instance
