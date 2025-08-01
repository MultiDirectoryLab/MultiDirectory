"""Conftest for testing audit policy router.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncIterator

import pytest_asyncio
from dishka import (
    AsyncContainer,
    Provider,
    Scope,
    make_async_container,
    provide,
)

from config import Settings
from ldap_protocol.policies.audit.destination_dao import AuditDestinationDAO
from ldap_protocol.policies.audit.policies_dao import AuditPoliciesDAO
from ldap_protocol.policies.audit.service import AuditService
from tests.conftest import TestProvider


class TestLocalProvider(Provider):
    """Test provider for local scope."""

    audit_policy_dao = provide(AuditPoliciesDAO, scope=Scope.REQUEST)
    audit_destination_dao = provide(AuditDestinationDAO, scope=Scope.REQUEST)
    audit_service = provide(AuditService, scope=Scope.REQUEST)


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


@pytest_asyncio.fixture(scope="function")
async def audit_service(
    container: AsyncContainer,
) -> AsyncIterator[AuditService]:
    """Fixture to provide the audit service."""
    async with container(scope=Scope.REQUEST) as container:
        yield await container.get(AuditService)
