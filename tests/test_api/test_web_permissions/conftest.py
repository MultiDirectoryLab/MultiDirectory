"""Create network policies and users for shadow api tests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import Any, AsyncIterator, Literal
from unittest.mock import Mock

import pytest_asyncio
from dishka import (
    AsyncContainer,
    Provider,
    Scope,
    make_async_container,
    provide,
)

from config import Settings
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
    if isinstance(param_type, int):
        return 1
    elif isinstance(param_type, str):
        return "test"
    else:
        mock = Mock()
        mock.id = 1
        return mock
