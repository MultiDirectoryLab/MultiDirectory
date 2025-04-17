"""Create network policies and users for shadow api tests.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest_asyncio
from fastapi import status
from httpx import AsyncClient
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.ldap_codes import LDAPCodes
from models import CatalogueSetting


class ProxyRequestModel(BaseModel):
    """Model for the proxy request.

    Attributes:
        principal: Unique user identifier
        ip: IP address from which the request is made

    """

    principal: str
    ip: str


@pytest_asyncio.fixture
async def adding_mfa_keys(session: AsyncSession) -> None:
    """Test add user like keycloak."""
    session.add(
        CatalogueSetting(name="mfa_secret", value="123"),
    )
    session.add(CatalogueSetting(name="mfa_key", value="123"))
    session.add(
        CatalogueSetting(name="mfa_key_ldap", value="123"),
    )
    session.add(CatalogueSetting(name="mfa_secret_ldap", value="123"))
    await session.commit()


@pytest_asyncio.fixture
async def adding_mfa_user_and_group(
    http_client: AsyncClient,
    unbound_http_client: AsyncClient,
) -> dict:
    """Add mfa user and group."""
    response = await http_client.post(
        "/entry/add",
        json={
            "entry": "cn=mfa_group,cn=groups,dc=md,dc=test",
            "password": None,
            "attributes": [
                {
                    "type": "name",
                    "vals": ["mfa_group"],
                },
                {
                    "type": "cn",
                    "vals": ["mfa_group"],
                },
                {
                    "type": "objectClass",
                    "vals": ["organization", "top", "group"],
                },
                {"type": "groupType", "vals": ["-2147483646"]},
                {"type": "o", "vals": ["MultiDirectory"]},
            ],
        },
    )

    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data["resultCode"] == LDAPCodes.SUCCESS

    test_user_dn = "cn=mfa_user,dc=md,dc=test"
    test_user_email = "mfa_user@md.test"
    user_password = "P@ssw0rd"  # noqa: S105

    response = await http_client.post(
        "/entry/add",
        json={
            "entry": test_user_dn,
            "password": user_password,
            "attributes": [
                {
                    "type": "name",
                    "vals": ["mfa_user"],
                },
                {
                    "type": "cn",
                    "vals": ["mfa_user"],
                },
                {
                    "type": "sAMAccountName",
                    "vals": ["Test"],
                },
                {
                    "type": "mail",
                    "vals": [test_user_email],
                },
                {
                    "type": "userPrincipalName",
                    "vals": [test_user_email],
                },
                {
                    "type": "displayName",
                    "vals": ["MFA User"],
                },
                {
                    "type": "memberOf",
                    "vals": [
                        "cn=mfa_group,cn=groups,dc=md,dc=test",
                        "cn=domain admins,cn=groups,dc=md,dc=test",
                    ],
                },
                {
                    "type": "userAccountControl",
                    "vals": ["512"],
                },
                {
                    "type": "objectClass",
                    "vals": ["organization", "top", "user"],
                },
                {"type": "nsAccountLock", "vals": ["FALSE"]},
                {"type": "shadowExpire", "vals": ["0"]},
                {"type": "o", "vals": ["MultiDirectory"]},
            ],
        },
    )

    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data["resultCode"] == LDAPCodes.SUCCESS

    auth = await unbound_http_client.post(
        "auth/",
        data={
            "username": test_user_email,
            "password": user_password,
        },
    )

    assert response.status_code == status.HTTP_200_OK
    assert auth.cookies.get("id")

    return ProxyRequestModel(
        principal=test_user_email,
        ip="127.0.0.1",
    ).model_dump()
