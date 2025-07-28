"""Test shedule functions.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from extra.scripts.check_ldap_principal import check_ldap_principal
from extra.scripts.principal_block_user_sync import principal_block_sync
from extra.scripts.uac_sync import disable_accounts
from extra.scripts.unlock_expired_users import unlock_expired_users
from extra.scripts.update_krb5_config import update_krb5_config
from ldap_protocol.kerberos import AbstractKadmin


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_disable_accounts(
    session: AsyncSession,
    settings: Settings,
    kadmin: AbstractKadmin,
) -> None:
    """Test disable_accounts."""
    await disable_accounts(
        session=session,
        kadmin=kadmin,
        settings=settings,
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_principal_block_sync(
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Test principal_block_sync."""
    await principal_block_sync(
        session=session,
        settings=settings,
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_check_ldap_principal(
    session: AsyncSession,
    settings: Settings,
    kadmin: AbstractKadmin,
) -> None:
    """Test check_ldap_principal."""
    await check_ldap_principal(
        session=session,
        kadmin=kadmin,
        settings=settings,
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_update_krb5_config(
    session: AsyncSession,
    settings: Settings,
    kadmin: AbstractKadmin,
) -> None:
    """Test update_krb5_config."""
    await update_krb5_config(
        session=session,
        kadmin=kadmin,
        settings=settings,
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
@pytest.mark.usefixtures("setup_session")
async def test_unlock_expired_users(
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Test unlock_expired_users."""
    await unlock_expired_users(
        session=session,
        settings=settings,
    )
