"""MFA methods.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import CatalogueSetting


@pytest.mark.asyncio
async def test_set_and_remove_mfa(
    http_client: httpx.AsyncClient,
    session: AsyncSession,
) -> None:
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

    assert await session.scalar(
        select(CatalogueSetting)
        .filter_by(name="mfa_key", value="123"),
    )  # fmt: skip
    assert await session.scalar(
        select(CatalogueSetting)
        .filter_by(name="mfa_secret", value="123"),
    )  # fmt: skip

    response = await http_client.delete("/multifactor/keys?scope=http")

    assert response.status_code == 200

    assert not await session.scalar(
        select(CatalogueSetting)
        .filter_by(name="mfa_key", value="123"),
    )  # fmt: skip
    assert not await session.scalar(
        select(CatalogueSetting)
        .filter_by(name="mfa_secret", value="123"),
    )  # fmt: skip
