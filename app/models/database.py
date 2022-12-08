"""Database primitives."""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base

from config import settings

engine = create_async_engine(settings.POSTGRES_URI)
async_session = AsyncSession(engine, expire_on_commit=False)

Base = declarative_base()
