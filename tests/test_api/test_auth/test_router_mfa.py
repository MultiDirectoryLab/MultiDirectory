"""MFA methods.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from datetime import datetime, timedelta

import httpx
import pytest
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.oauth2 import authenticate_user
from models import CatalogueSetting
from tests.conftest import TestCreds


@pytest.mark.asyncio
async def test_set_and_remove_mfa(
        http_client: httpx.AsyncClient,
        session: AsyncSession) -> None:
    """Set mfa."""
    response = await http_client.post(
        "/multifactor/setup",
        json={
            "mfa_key": "123",
            "mfa_secret": "123",
            "is_ldap_scope": False,
        },
    )

    assert response.json() is True
    assert response.status_code == 201

    assert await session.scalar(select(CatalogueSetting).filter_by(
        name="mfa_key", value="123"))
    assert await session.scalar(select(CatalogueSetting).filter_by(
        name="mfa_secret", value="123"))

    response = await http_client.delete("/multifactor/keys?scope=http")

    assert response.status_code == 200

    assert not await session.scalar(select(CatalogueSetting).filter_by(
        name="mfa_key", value="123"))
    assert not await session.scalar(select(CatalogueSetting).filter_by(
        name="mfa_secret", value="123"))


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_connect_mfa(
    http_client: httpx.AsyncClient,
    session: AsyncSession,
    creds: TestCreds,
) -> None:
    """Test websocket mfa."""
    session.add(
        CatalogueSetting(name="mfa_secret", value="123"),
    )
    session.add(CatalogueSetting(name="mfa_key", value="123"))
    await session.commit()

    redirect_url = "example.com"

    response = await http_client.post(
        "/multifactor/connect",
        data={"username": creds.un, "password": creds.pw})

    assert response.json() == {"status": "pending", "message": redirect_url}

    user = await authenticate_user(session, creds.un, creds.pw)

    assert user

    exp = datetime.now() + timedelta(minutes=5)

    token = jwt.encode({"aud": "123", "uid": user.id, "exp": exp}, "123")

    response = await http_client.post(
        "/multifactor/create",
        data={"accessToken": token}, follow_redirects=False)

    assert response.status_code == 302
    assert response.cookies.get("id")
