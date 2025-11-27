"""Create network policies and users for shadow api tests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncIterator, TypeVar
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

_R = TypeVar("_R")


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
