"""Test LDF version router."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from entities import LdfVersion
from enums import LdfVersionStatus


@pytest.mark.asyncio
async def test_get_ldf_versions_paginated(
    http_client: AsyncClient,
    session: AsyncSession,
) -> None:
    """Test paginated LDF versions list."""
    now = datetime.now(timezone.utc)
    session.add_all(
        [
            LdfVersion(
                version="sch1",
                status=LdfVersionStatus.SUCCESS,
                d_create=now - timedelta(minutes=2),
            ),
            LdfVersion(
                version="sch2",
                status=LdfVersionStatus.ERROR,
                d_create=now - timedelta(minutes=1),
            ),
            LdfVersion(
                version="sch3",
                status=LdfVersionStatus.SUCCESS,
                d_create=now,
            ),
        ],
    )
    await session.commit()

    response = await http_client.get(
        "/ldf/versions?page_number=1&page_size=2",
    )

    assert response.status_code == status.HTTP_200_OK
    payload = response.json()

    assert payload["metadata"]["page_number"] == 1
    assert payload["metadata"]["page_size"] == 2
    assert payload["metadata"]["total_count"] == 3
    assert payload["metadata"]["total_pages"] == 2
    assert len(payload["items"]) == 2
    assert payload["items"][0]["version"] == "sch3"
    assert payload["items"][1]["version"] == "sch2"
