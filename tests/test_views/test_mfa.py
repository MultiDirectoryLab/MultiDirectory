"""MFA methods."""

import httpx
import pytest
from sqlalchemy import select

from app.extra import TEST_DATA, setup_enviroment
from app.models import CatalogueSetting


@pytest.mark.asyncio()
async def test_set_mfa(http_client: httpx.AsyncClient, session):
    """Set mfa."""
    await setup_enviroment(session, dn="md.test", data=TEST_DATA)
    await session.commit()

    auth = await http_client.post("auth/token/get", data={
        "username": "user0", "password": "password"})
    login_headers = {'Authorization': f"Bearer {auth.json()['access_token']}"}

    response = await http_client.post(
        "/multifactor/setup", headers=login_headers,
        json={'mfa_key': "123", 'mfa_secret': "123"})

    assert response.json() is True
    assert response.status_code == 201

    assert await session.scalar(select(CatalogueSetting).filter_by(
        name="mfa_key", value="123"))
    assert await session.scalar(select(CatalogueSetting).filter_by(
        name="mfa_secret", value="123"))
