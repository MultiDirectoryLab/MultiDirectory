"""Test shedule functions.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from extra.scripts.add_domain_controller import add_domain_controller
from extra.scripts.check_ldap_principal import check_ldap_principal
from extra.scripts.principal_block_user_sync import principal_block_sync
from extra.scripts.uac_sync import disable_accounts
from extra.scripts.update_krb5_config import update_krb5_config
from ldap_protocol.kerberos import AbstractKadmin
from ldap_protocol.ldap_schema.entity_type.entity_type_use_case import EntityTypeUseCase
from ldap_protocol.rid_manager import ObjectSIDUseCase
from ldap_protocol.rid_manager.rid_set_use_case import RIDSetUseCase
from ldap_protocol.roles.role_use_case import RoleUseCase


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_disable_accounts(session: AsyncSession, settings: Settings, kadmin: AbstractKadmin) -> None:
    """Test disable_accounts."""
    await disable_accounts(session=session, kadmin=kadmin, settings=settings)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_principal_block_sync(session: AsyncSession, settings: Settings) -> None:
    """Test principal_block_sync."""
    await principal_block_sync(session=session, settings=settings)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_check_ldap_principal(session: AsyncSession, settings: Settings, kadmin: AbstractKadmin) -> None:
    """Test check_ldap_principal."""
    await check_ldap_principal(session=session, kadmin=kadmin, settings=settings)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_update_krb5_config(session: AsyncSession, settings: Settings) -> None:
    """Test update_krb5_config."""
    await update_krb5_config(session=session, settings=settings)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_add_domain_controller(
    session: AsyncSession,
    settings: Settings,
    role_use_case: RoleUseCase,
    entity_type_use_case: EntityTypeUseCase,
    object_sid_use_case: ObjectSIDUseCase,
    rid_set_use_case: RIDSetUseCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test add domain controller."""
    monkeypatch.setattr(settings, "HOST_MACHINE_SHORT_NAME", f"{settings.HOST_MACHINE_SHORT_NAME}-test")
    await add_domain_controller(
        settings=settings,
        session=session,
        role_use_case=role_use_case,
        entity_type_use_case=entity_type_use_case,
        object_sid_use_case=object_sid_use_case,
        rid_set_use_case=rid_set_use_case,
    )
