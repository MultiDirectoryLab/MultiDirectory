"""Test AttributeTypeUseCase.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest

from ldap_protocol.ldap_schema.attribute_type_use_case import (
    AttributeTypeUseCase,
)
from ldap_protocol.ldap_schema.dto import AttributeTypeDTO


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_attribute_type_system_flags_use_case_is_not_replicated(
    attribute_type_use_case: AttributeTypeUseCase,
) -> None:
    """Test AttributeType is not replicated."""
    await attribute_type_use_case.create(
        AttributeTypeDTO(
            oid="1.2.3.4",
            name="objectClass123",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=True,
            no_user_modification=False,
            is_system=False,
            system_flags=0x00000001,  # ATTR_NOT_REPLICATED
            is_included_anr=False,
        ),
    )
    assert not await attribute_type_use_case.is_attr_replicated(
        "objectClass123",
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_attribute_type_system_flags_use_case_is_replicated(
    attribute_type_use_case: AttributeTypeUseCase,
) -> None:
    """Test AttributeType is replicated."""
    await attribute_type_use_case.create(
        AttributeTypeDTO(
            oid="1.2.3.4",
            name="objectClass123",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=True,
            no_user_modification=False,
            is_system=False,
            system_flags=0x00000000,  # ATTR_NOT_REPLICATED
            is_included_anr=False,
        ),
    )
    assert await attribute_type_use_case.is_attr_replicated("objectClass123")
    await attribute_type_use_case.set_attr_replication_flag(
        "objectClass123",
        False,
    )
    assert not await attribute_type_use_case.is_attr_replicated(
        "objectClass123",
    )
