"""Test Object Class CRUDs.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_schema.attribute_type_crud import (
    create_attribute_type,
    delete_attribute_types_by_names,
    get_attribute_type_by_name,
)


@pytest.mark.asyncio
async def test_delete_attribute_types_by_names(session: AsyncSession) -> None:
    """Test delete attribute types by names."""
    attribute_type_data: dict = {
        "oid": "1.2.3.4.5",
        "name": "customTestAttribute",
        "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
        "single_value": True,
        "no_user_modification": False,
        "is_system": False,
    }
    attribute_type_name = attribute_type_data["name"]

    await create_attribute_type(session=session, **attribute_type_data)
    attribute_type = await get_attribute_type_by_name(
        session=session, attribute_type_name=attribute_type_name
    )
    assert attribute_type is not None

    await delete_attribute_types_by_names(
        session=session, attribute_type_names=[attribute_type_name]
    )
    attribute_type = await get_attribute_type_by_name(
        session=session, attribute_type_name=attribute_type_name
    )
    assert attribute_type is None
