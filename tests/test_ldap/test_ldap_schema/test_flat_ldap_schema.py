"""Test flat LDAP Schema.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_schema.flat_ldap_schema import get_flat_ldap_schema


@pytest.mark.asyncio
async def test_get_flat_ldap_schema(session: AsyncSession) -> None:
    """Get flat schema."""
    flat_schema = await get_flat_ldap_schema(session)
    assert flat_schema is not None
