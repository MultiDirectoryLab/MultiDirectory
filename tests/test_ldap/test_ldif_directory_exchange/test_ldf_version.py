"""Test LDF version use case."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import AsyncIterator

import pytest
import pytest_asyncio
from dishka import AsyncContainer, Scope
from sqlalchemy.ext.asyncio import AsyncSession

from entities import LdfVersion
from enums import LdfVersionStatus
from ldap_protocol.ldif_directory_exchange.ldf_version.dto import LdfVersionDTO
from ldap_protocol.ldif_directory_exchange.ldf_version.exceptions import (
    LdfVersionNotFoundError,
)
from ldap_protocol.ldif_directory_exchange.ldf_version.ldf_version_use_case import (  # noqa: E501
    LdfVersionUseCase,
)
from ldap_protocol.utils.pagination import PaginationParams


@pytest_asyncio.fixture(scope="function")
async def ldf_version_use_case(
    container: AsyncContainer,
) -> AsyncIterator[LdfVersionUseCase]:
    """Get LDF version use case."""
    async with container(scope=Scope.REQUEST) as request_container:
        yield await request_container.get(LdfVersionUseCase)


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_create_ldf_version(
    ldf_version_use_case: LdfVersionUseCase,
) -> None:
    """Test creating and fetching an LDF version."""
    dto = LdfVersionDTO(
        version="sch14.ldf",
        status=LdfVersionStatus.SUCCESS,
    )
    await ldf_version_use_case.create(dto)

    result = await ldf_version_use_case.get("sch14.ldf")
    assert result.version == "sch14.ldf"
    assert result.status == LdfVersionStatus.SUCCESS
    assert result.d_create is not None


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_update_status(
    ldf_version_use_case: LdfVersionUseCase,
) -> None:
    """Test updating LDF version status."""
    dto = LdfVersionDTO(
        version="sch5.ldf",
        status=LdfVersionStatus.SUCCESS,
    )
    await ldf_version_use_case.create(dto)

    await ldf_version_use_case.update_status(
        "sch5.ldf",
        LdfVersionStatus.ERROR,
    )

    result = await ldf_version_use_case.get("sch5.ldf")
    assert result.status == LdfVersionStatus.ERROR


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_get_latest_success_and_error(
    session: AsyncSession,
    ldf_version_use_case: LdfVersionUseCase,
) -> None:
    """Test fetching latest success and error versions."""
    now = datetime.now(timezone.utc)
    session.add_all(
        [
            LdfVersion(
                version="sch14.ldf",
                status=LdfVersionStatus.SUCCESS,
                d_create=now - timedelta(minutes=2),
            ),
            LdfVersion(
                version="sch15.ldf",
                status=LdfVersionStatus.SUCCESS,
                d_create=now - timedelta(minutes=1),
            ),
            LdfVersion(
                version="sch16.ldf",
                status=LdfVersionStatus.ERROR,
                d_create=now,
            ),
        ],
    )
    await session.commit()

    latest_success = await ldf_version_use_case.get_latest_success()
    assert latest_success.version == "sch15.ldf"

    latest_error = await ldf_version_use_case.get_latest_error()
    assert latest_error.version == "sch16.ldf"


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_get_latest_success_raises_when_empty(
    ldf_version_use_case: LdfVersionUseCase,
) -> None:
    """Test latest success raises when no versions exist."""
    with pytest.raises(
        LdfVersionNotFoundError,
        match=r"No LDF version with status 'success'\.",
    ):
        await ldf_version_use_case.get_latest_success()


@pytest.mark.asyncio
@pytest.mark.usefixtures("session")
async def test_get_paginator(
    session: AsyncSession,
    ldf_version_use_case: LdfVersionUseCase,
) -> None:
    """Test paginated LDF version list."""
    now = datetime.now(timezone.utc)
    session.add_all(
        [
            LdfVersion(
                version="sch23.ldf",
                status=LdfVersionStatus.SUCCESS,
                d_create=now - timedelta(minutes=2),
            ),
            LdfVersion(
                version="sch24.ldf",
                status=LdfVersionStatus.ERROR,
                d_create=now - timedelta(minutes=1),
            ),
            LdfVersion(
                version="sch25.ldf",
                status=LdfVersionStatus.SUCCESS,
                d_create=now,
            ),
        ],
    )
    await session.commit()

    result = await ldf_version_use_case.get_paginator(
        PaginationParams(page_number=1, page_size=2),
    )

    assert result.metadata.page_number == 1
    assert result.metadata.page_size == 2
    assert result.metadata.total_count == 3
    assert result.metadata.total_pages == 2
    assert {item.version for item in result.items} == {
        "sch25.ldf",
        "sch24.ldf",
    }

    paginator = await ldf_version_use_case.get_paginator(
        PaginationParams(page_number=1, page_size=10, query="sch23.ldf"),
    )
    assert [item.version for item in paginator.items] == ["sch23.ldf"]
