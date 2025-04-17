"""Test flat LDAP Schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_schema.flat_ldap_schema import get_flat_ldap_schema
from ldap_protocol.ldap_schema.object_class_crud import get_all_object_classes


@pytest.mark.asyncio
async def test_get_flat_ldap_schema(session: AsyncSession) -> None:
    """Get flat schema."""
    all_object_classes = await get_all_object_classes(session)
    flat_ldap_schema = await get_flat_ldap_schema(session)
    assert len(all_object_classes) == len(flat_ldap_schema)
    {
        key: (value[2], len(value[0]) + len(value[1]))
        for key, value in flat_ldap_schema.items()
    }
