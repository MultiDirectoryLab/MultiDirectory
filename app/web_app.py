"""Multidirectory api module."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from api import (
    auth_router,
    entry_router,
    mfa_router,
    network_router,
    pwd_router,
)
from config import VENDOR_VERSION, Settings, get_settings
from models.database import create_get_async_session, get_session

logger.add(
    "logs/json_ldap_{time:DD-MM-YYYY}.log",
    filter=lambda rec: "event" in rec["extra"],
    retention="10 days",
    rotation="1d",
    colorize=False,
)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create FastAPI app with dependencies overrides."""
    settings = settings or Settings()

    app = FastAPI(
        name="MultiDirectory",
        title="MultiDirectory",
        debug=settings.DEBUG,
        root_path="/api",
        version=VENDOR_VERSION,
    )
    origins = ["*"]
    app.dependency_overrides = {
        get_settings: lambda: settings,
        get_session: create_get_async_session(settings),
    }
    app.include_router(auth_router)
    app.include_router(entry_router)
    app.include_router(network_router)
    app.include_router(mfa_router)
    app.include_router(pwd_router)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return app
