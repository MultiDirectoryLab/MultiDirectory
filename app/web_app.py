"""Multidirectory api module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from dishka import make_async_container
from dishka.integrations.fastapi import setup_dishka
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api import (
    auth_router,
    entry_router,
    krb5_router,
    mfa_router,
    network_router,
    pwd_router,
)
from config import VENDOR_VERSION, Settings
from ioc import HTTPProvider, MainProvider, MFACredsProvider, MFAProvider


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create FastAPI app with dependencies overrides."""
    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        await app.state.dishka_container.close()

    settings = settings or Settings()

    app = FastAPI(
        name="MultiDirectory",
        title="MultiDirectory",
        debug=settings.DEBUG,
        root_path="/api",
        version=VENDOR_VERSION,
        lifespan=_lifespan,
    )
    origins = ["*"]
    app.include_router(auth_router)
    app.include_router(entry_router)
    app.include_router(network_router)
    app.include_router(mfa_router)
    app.include_router(pwd_router)
    app.include_router(krb5_router)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return app


def create_prod_app() -> FastAPI:
    """Create production app with container."""
    app = create_app()
    container = make_async_container(
        MainProvider(), MFAProvider(),
        HTTPProvider(), MFACredsProvider(),
        context={Settings: Settings()})

    setup_dishka(container, app)
    return app
