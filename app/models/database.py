"""Database primitives."""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from config import Settings

Base = declarative_base()


async def get_session():
    """Stub factory."""
    raise NotImplementedError


def get_engine(settings: Settings):  # noqa
    return create_async_engine(settings.POSTGRES_URI, pool_size=10)


def create_get_async_session(settings: Settings):
    """Acquire session creator func."""
    async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
        """Acquire session."""
        async_session = sessionmaker(
            get_engine(settings),
            expire_on_commit=False,
            class_=AsyncSession,
        )
        async with async_session() as session:
            yield session

    return get_async_session


def create_session_factory(settings: Settings):  # noqa
    from contextlib import asynccontextmanager
    get_async_session = create_get_async_session(settings)
    return asynccontextmanager(get_async_session)
