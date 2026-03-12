"""Test router config.

Copyright (c) 2026 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.auth.setup_gateway import SetupGateway
from ldap_protocol.ldap_schema.attribute_value_validator import (
    AttributeValueValidator,
)
from ldap_protocol.ldap_schema.entity_type.entity_type_dao import EntityTypeDAO
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import (
    EntityTypeUseCase,
)
from ldap_protocol.ldap_schema.object_class.object_class_dao import (
    ObjectClassDAO,
)
from ldap_protocol.utils.queries import get_base_directories
from password_utils import PasswordUtils
from tests.constants import TEST_SYSTEM_ADMIN_DATA


@pytest_asyncio.fixture(scope="function")
async def add_system_administrator(
    session: AsyncSession,
    password_utils: PasswordUtils,
    setup_session: None,  # noqa: ARG001
) -> None:
    """Create system administrator user for tests that require it."""
    attribute_value_validator = AttributeValueValidator()
    object_class_dao = ObjectClassDAO(session)
    entity_type_dao = EntityTypeDAO(
        session=session,
        attribute_value_validator=attribute_value_validator,
        object_class_dao=object_class_dao,
    )
    entity_type_use_case = EntityTypeUseCase(
        entity_type_dao=entity_type_dao,
        object_class_dao=object_class_dao,
    )

    setup_gateway = SetupGateway(
        session,
        password_utils,
        entity_type_use_case,
        attribute_value_validator=attribute_value_validator,
    )

    domain = (await get_base_directories(session))[0]
    await setup_gateway.create_dir(
        data=TEST_SYSTEM_ADMIN_DATA,
        is_system=True,
        domain=domain,
        parent=domain,
    )
