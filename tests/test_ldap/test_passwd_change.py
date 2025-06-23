"""Test password change.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from aioldap3 import LDAPConnection
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.utils.queries import get_user
from security import verify_password
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("_force_override_tls")
async def test_anonymous_pwd_change(
    session: AsyncSession,
    anonymous_ldap_client: LDAPConnection,
    creds: TestCreds,
) -> None:
    """Test anonymous pwd change."""
    user_dn = "cn=user0,ou=users,dc=md,dc=test"
    password = creds.pw
    new_test_password = "P@ssw0rd123"  # noqa: S105
    await anonymous_ldap_client.modify_password(
        new_test_password,
        user_dn,
        password,
    )

    user = await get_user(session, user_dn)
    assert user
    assert user.password

    assert verify_password(new_test_password, user.password)


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("_force_override_tls")
async def test_bind_pwd_change(
    session: AsyncSession,
    ldap_client: LDAPConnection,
    creds: TestCreds,
) -> None:
    """Test anonymous pwd change."""
    user_dn = "cn=user0,ou=users,dc=md,dc=test"
    password = creds.pw
    new_test_password = "P@ssw0rd123"  # noqa: S105
    await ldap_client.bind(user_dn, password)
    await ldap_client.modify_password(new_test_password, user_dn, password)

    user = await get_user(session, user_dn)

    assert user
    assert user.password

    assert verify_password(new_test_password, user.password)
