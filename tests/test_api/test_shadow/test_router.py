"""Test shadow api.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import MFAFlags, NetworkPolicy

from .conftest import ProxyRequestModel


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_shadow_api_non_existent_user(http_client: AsyncClient) -> None:
    """Test shadow api with non-existent user."""
    response = await http_client.post(
        "/shadow/mfa/push",
        json=ProxyRequestModel(
            principal="non-existent_user",
            ip="127.0.0.1",
        ).model_dump(),
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_shadow_api_without_network_policies(
    http_client: AsyncClient,
    adding_mfa_user_and_group: dict,
    session: AsyncSession,
) -> None:
    """Test shadow api without network policy."""
    await session.execute(delete(NetworkPolicy))

    response = await http_client.post(
        "/shadow/mfa/push",
        json=adding_mfa_user_and_group,
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_shadow_api_without_kerberos_protocol(
    http_client: AsyncClient,
    adding_mfa_user_and_group: dict,
    session: AsyncSession,
) -> None:
    """Test shadow api without network policy with kerberos protocol."""
    await session.execute(
        update(NetworkPolicy)
        .values({NetworkPolicy.is_kerberos: False}),
    )

    response = await http_client.post(
        "/shadow/mfa/push",
        json=adding_mfa_user_and_group,
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_shadow_api_with_disable_mfa(
    http_client: AsyncClient,
    adding_mfa_user_and_group: dict,
) -> None:
    """Test shadow api with disable mfa."""
    response = await http_client.post(
        "/shadow/mfa/push",
        json=adding_mfa_user_and_group,
    )

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_shadow_api_whitelist_without_user_group(
    http_client: AsyncClient,
    adding_mfa_user_and_group: dict,
    session: AsyncSession,
) -> None:
    """Test shadow api whitelist without user group."""
    await session.execute(
        update(NetworkPolicy)
        .values({NetworkPolicy.mfa_status: MFAFlags.WHITELIST}),
    )

    response = await http_client.post(
        "/shadow/mfa/push",
        json=adding_mfa_user_and_group,
    )

    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
async def test_shadow_api_enable_mfa(
    http_client: AsyncClient,
    adding_mfa_user_and_group: dict,
    session: AsyncSession,
) -> None:
    """Test shadow api enable mfa."""
    await session.execute(
        update(NetworkPolicy)
        .values({NetworkPolicy.mfa_status: MFAFlags.ENABLED}),
    )

    response = await http_client.post(
        "/shadow/mfa/push",
        json=adding_mfa_user_and_group,
    )

    assert response.status_code == status.HTTP_200_OK
