"""Database primitives."""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from config import settings

engine = create_async_engine(settings.POSTGRES_URI)
async_session = sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)

Base = declarative_base()


async def get_session():
    """Stub factory."""
    raise NotImplementedError


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Acquire session."""
    async with async_session() as session:
        yield session
