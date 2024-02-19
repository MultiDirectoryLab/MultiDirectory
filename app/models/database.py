"""Database primitives."""

from typing import AsyncContextManager, AsyncGenerator, Callable

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

from config import Settings

Base = declarative_base()


async def get_session() -> None:
    """Stub factory."""
    raise NotImplementedError


def get_engine(settings: Settings) -> AsyncEngine:  # noqa
    return create_async_engine(str(settings.POSTGRES_URI), pool_size=10)


def create_get_async_session(
    settings: Settings,
) -> Callable[[], AsyncGenerator[AsyncSession, None]]:
    """Acquire session creator func."""
    engine = get_engine(settings)

    async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
        """Acquire session."""
        async_session = sessionmaker(
            engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )
        async with async_session() as session:
            yield session

    return get_async_session


def create_session_factory(
    settings: Settings,
) -> Callable[..., AsyncContextManager[AsyncSession]]:
    """Create session factory."""
    from contextlib import asynccontextmanager
    get_async_session = create_get_async_session(settings)
    return asynccontextmanager(get_async_session)
