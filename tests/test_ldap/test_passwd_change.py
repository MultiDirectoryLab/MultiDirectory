"""Test password change.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from functools import partial

import pytest
from aioldap3 import LDAPConnection
from ldap3 import Connection
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.dialogue import LDAPSession
from ldap_protocol.kerberos.base import AbstractKadmin
from ldap_protocol.ldap_codes import LDAPCodes
from ldap_protocol.ldap_requests.extended import (
    ExtendedRequest,
    PasswdModifyRequestValue,
)
from ldap_protocol.utils.queries import get_user
from security import verify_password
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("_force_override_tls")
async def test_anonymous_pwd_change(
    session: AsyncSession,
    ldap_client: LDAPConnection,
    ldap_session: LDAPSession,
    kadmin: AbstractKadmin,
    settings: Settings,
    creds: TestCreds,
) -> None:
    """Test anonymous pwd change."""
    user_dn = "cn=user0,ou=users,dc=md,dc=test"
    password = creds.pw
    new_test_password = "Password123"  # noqa
    await ldap_client.bind(user_dn, password)

    request_value = PasswdModifyRequestValue(
        user_identity=user_dn,
        old_password=SecretStr(password),
        new_password=SecretStr(new_test_password),
    )

    ex_request = ExtendedRequest(
        request_name="1.3.6.1.4.1.4203.1.11.1", request_value=request_value
    )

    async for response in ex_request.handle(
        ldap_session=ldap_session,
        session=session,
        kadmin=kadmin,
        settings=settings,
    ):
        assert response.result_code == LDAPCodes.SUCCESS

    user = await get_user(session, user_dn)
    assert user
    assert user.password

    assert verify_password(new_test_password, user.password)

    await ldap_client.unbind()


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("_force_override_tls")
async def test_bind_pwd_change(
    session: AsyncSession,
    ldap_client: LDAPConnection,
    creds: TestCreds,
    ldap_session: LDAPSession,
    kadmin: AbstractKadmin,
    settings: Settings,
) -> None:
    """Test anonymous pwd change."""
    user_dn = "cn=user0,ou=users,dc=md,dc=test"
    password = creds.pw
    new_test_password = "Password123"  # noqa
    await ldap_client.bind(user_dn, password)

    request_value = PasswdModifyRequestValue(
        user_identity=user_dn,
        old_password=SecretStr(password),
        new_password=SecretStr(new_test_password),
    )

    ex_request = ExtendedRequest(
        request_name="1.3.6.1.4.1.4203.1.11.1", request_value=request_value
    )

    async for response in ex_request.handle(
        ldap_session=ldap_session,
        session=session,
        kadmin=kadmin,
        settings=settings,
    ):
        assert response.result_code == LDAPCodes.SUCCESS

    user = await get_user(session, user_dn)

    assert user
    assert user.password

    assert verify_password(new_test_password, user.password)

    await ldap_client.unbind()
