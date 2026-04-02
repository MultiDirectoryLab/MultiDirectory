"""Conftest for LDAP schema AttributeType tests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncIterator

import pytest_asyncio
from dishka import AsyncContainer, Scope

from ldap_protocol.ldap_schema.attribute_type.attribute_type_use_case import (
    AttributeTypeUseCase,
)


@pytest_asyncio.fixture(scope="function")
async def attribute_type_use_case(
    container: AsyncContainer,
) -> AsyncIterator[AttributeTypeUseCase]:
    """Get di attribute_type_use_case."""
    async with container(scope=Scope.REQUEST) as container:
        yield await container.get(AttributeTypeUseCase)
