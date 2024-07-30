"""MFA methods.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.oauth2 import authenticate_user, create_token
from app.config import Settings
from app.models import CatalogueSetting
from ldap_protocol.multifactor import MultifactorAPI  # sync object ids
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
async def test_set_mfa(
        http_client: httpx.AsyncClient,
        session: AsyncSession,
        login_headers: dict) -> None:
    """Set mfa."""
    response = await http_client.post(
        "/multifactor/setup",
        headers=login_headers,
        json={
            'mfa_key': "123",
            'mfa_secret': "123",
            'is_ldap_scope': False,
        },
    )

    assert response.json() is True
    assert response.status_code == 201

    assert await session.scalar(select(CatalogueSetting).filter_by(
        name="mfa_key", value="123"))
    assert await session.scalar(select(CatalogueSetting).filter_by(
        name="mfa_secret", value="123"))


@pytest.mark.asyncio
@pytest.mark.usefixtures('setup_session')
async def test_connect_mfa(
    http_client: httpx.AsyncClient,
    app: FastAPI,
    session: AsyncSession,
    settings: Settings,
    creds: TestCreds,
) -> None:
    """Test websocket mfa."""
    session.add(
        CatalogueSetting(name='mfa_secret', value=settings.SECRET_KEY),
    )
    session.add(CatalogueSetting(name='mfa_key', value='123'))
    await session.commit()

    redirect_url = "example.com"

    response = await http_client.post(
        '/multifactor/connect',
        data={'username': creds.un, 'password': creds.pw})

    assert response.json() == {'status': 'pending', 'message': redirect_url}

    user = await authenticate_user(session, creds.un, creds.pw)

    assert user

    token = create_token(
        user.id,
        settings.SECRET_KEY,
        settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        grant_type='multifactor',  # type: ignore
        extra_data={'aud': '123'})

    response = await http_client.post(
        '/multifactor/create',
        data={'accessToken': token}, follow_redirects=False)

    assert response.status_code == 302
    assert response.cookies == {'access_token': token}
