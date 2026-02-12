"""Test AttributeTypeUseCase.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest

from ldap_protocol.ldap_schema.attribute_type_use_case import (
    AttributeTypeUseCase,
)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_attribute_type_system_flags_use_case_is_not_replicated(
    attribute_type_use_case: AttributeTypeUseCase,
) -> None:
    """Test AttributeType is not replicated."""
    assert not await attribute_type_use_case.is_attr_replicated("netbootSCPBL")


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_attribute_type_system_flags_use_case_is_replicated(
    attribute_type_use_case: AttributeTypeUseCase,
) -> None:
    """Test AttributeType is replicated."""
    assert await attribute_type_use_case.is_attr_replicated("objectClass")
    await attribute_type_use_case.set_attr_replication_flag(
        "objectClass",
        False,
    )
    assert not await attribute_type_use_case.is_attr_replicated("objectClass")
