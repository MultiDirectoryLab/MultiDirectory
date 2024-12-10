"""Simple server for forwarding MFA requests.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any, AsyncIterator

import httpx
from fastapi import APIRouter, Body, Depends, FastAPI, status
from sqlalchemy import Column
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.future import select
from sqlalchemy.orm import sessionmaker

logging.basicConfig(level=logging.INFO)

push_router = APIRouter(tags=["push"])

ENV = os.environ.get("ENV", "dev")
# TODO: Replace with real URL
MFA_BASE_URI = "https://api.multifactor.ru"  \
    if ENV == "dev" else "https://api.multifactor.ru"
DATABASE_URL = "postgresql+psycopg://user1:password123@postgres/postgres"

Base = declarative_base()


class CatalogueSetting(Base):
    """Catalogue params unit."""

    __tablename__ = "Settings"

    id: int = Column(primary_key=True)  # noqa
    name: str = Column()
    value: str = Column()


@dataclass(frozen=True)
class Creds:
    """Creds for mfa."""

    key: str | None
    secret: str | None


async def get_mfa_http_creds(session: AsyncSession) -> Creds | None:
    """Get API creds."""
    query = select(CatalogueSetting).where(
        CatalogueSetting.name.in_(["mfa_key", "mfa_secret"]))

    vals = await session.scalars(query)
    secrets = {s.name: s.value for s in vals.all()}

    key = secrets.get("mfa_key")
    secret = secrets.get("mfa_secret")

    if not key or not secret:
        return None

    return Creds(key, secret)


class MultifactorService:
    """Service for sending requests to the Multifactor API."""

    AUTH_URL_USERS = "/access/requests/md"

    def __init__(self, base_url: str, key: str, secret: str):
        """Initialize the service."""
        self.base_url = base_url
        self.auth: tuple[str, str] = (key, secret)
        self.client = httpx.AsyncClient(base_url=self.base_url)

    async def send_user_request(self, principal: str) -> dict[str, Any]:
        """Send a user authentication request to the Multifactor API."""
        logging.info(f"{self.auth}")
        response = await self.client.post(
            self.AUTH_URL_USERS,
            json={
                "Identity": principal,
                "passCode": "m",
                "GroupPolicyPreset": {},
            },
            auth=self.auth,
        )
        logging.info(f"{response.status_code}")
        logging.info(f"{response.text}")
        return response.json()


def get_mfa_service() -> MultifactorService:
    """Stub for getting mfa service."""
    raise NotImplementedError


@push_router.post("/get/push/principal", status_code=status.HTTP_200_OK)
async def proxy_request(
    mfa_service: Annotated[MultifactorService, Depends(get_mfa_service)],
    principal: Annotated[str, Body(embed=True)],
) -> None:
    """Proxy request to mfa."""
    return await mfa_service.send_user_request(principal)


def create_app() -> FastAPI:
    """Create FastAPI app."""
    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        loop = asyncio.get_running_loop()

        engine = create_async_engine(DATABASE_URL, echo=True)
        async_session = sessionmaker(
            engine, expire_on_commit=False, class_=AsyncSession,
        )

        async def try_set_mfa_service(app: FastAPI) -> None:
            while not getattr(app.state, "mfa_service", None):
                try:
                    async with async_session() as session:
                        creds = await get_mfa_http_creds(session)
                        if creds:
                            service = MultifactorService(
                                base_url=MFA_BASE_URI,
                                key=creds.key,
                                secret=creds.secret,
                            )
                            app.state.mfa_service = service

                except TimeoutError:
                    await asyncio.sleep(1)
                else:
                    return

        loop.create_task(try_set_mfa_service(app))
        yield
        if getattr(app.state, "mfa_service", None):
            await app.state.mfa_service.client.aclose()
            del app.state.mfa_service

    app = FastAPI(
        name="MFAProxy",
        title="MFAProxy",
        lifespan=_lifespan,
    )

    def _get_mfa_service() -> MultifactorService:
        return app.state.mfa_service

    app.dependency_overrides = {
        get_mfa_service: _get_mfa_service,
    }

    app.include_router(push_router)
    return app
